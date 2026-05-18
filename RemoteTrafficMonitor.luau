local RemoteTrafficMonitor = {}

local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local ServerScriptService = game:GetService("ServerScriptService")

local Constants = require(ReplicatedStorage:WaitForChild("RSF_Shared"):WaitForChild("Constants"):WaitForChild("SecurityConstants"))
local Utilities = require(ReplicatedStorage:WaitForChild("RSF_Shared"):WaitForChild("Utilities"):WaitForChild("Utilities"))

local SuspicionScorer
local SAMPLE_WINDOW = 60
local MAX_PAYLOAD_SIZE = 2048
local ANOMALY_Z_THRESHOLD = 3.5
local MIN_SAMPLES = 5

local trafficProfiles: { [number]: {
	userId: number,
	remotes: { [string]: {
		remoteName: string,
		remotePath: string,
		totalFires: number,
		lastFireTime: number,
		fireTimestamps: { number },
		payloadSizes: { number },
		avgPayloadSize: number,
		avgFireRate: number,
		knownRemote: boolean,
	} },
	totalFires: number,
	anomalyCount: number,
} } = {}

local knownRemoteWhitelist: { [string]: boolean } = {}
local monitoredRemotes: { [RemoteEvent]: boolean } = {}
local initialized = false

local function avg(t: { number }): number
	if #t == 0 then return 0 end
	local s = 0
	for _, v in ipairs(t) do s += v end
	return s / #t
end

local function stddev(t: { number }, a: number): number
	if #t < 2 then return 0 end
	local v = 0
	for _, x in ipairs(t) do v += (x - a) ^ 2 end
	return math.sqrt(v / #t)
end

local function getOrCreateProfile(userId: number)
	local p = rawget(trafficProfiles, userId)
	if p then return p end
	local profile = { userId = userId, remotes = {}, totalFires = 0, anomalyCount = 0 }
	rawset(trafficProfiles, userId, profile)
	return profile
end

local function getOrCreateRecord(profile, remoteName: string, remotePath: string, isKnown: boolean)
	local r = rawget(profile.remotes, remoteName)
	if r then return r end
	local record = {
		remoteName = remoteName,
		remotePath = remotePath,
		totalFires = 0,
		lastFireTime = 0,
		fireTimestamps = {},
		payloadSizes = {},
		avgPayloadSize = 0,
		avgFireRate = 0,
		knownRemote = isKnown,
	}
	rawset(profile.remotes, remoteName, record)
	return record
end

local function estimateSize(payload: any): number
	local ok, encoded = pcall(function()
		return game:GetService("HttpService"):JSONEncode(payload)
	end)
	if ok and encoded then return #encoded end
	return tostring(payload) and #tostring(payload) or 0
end

local function pruneTimestamps(t: { number })
	local cutoff = os.time() - SAMPLE_WINDOW
	local i = 1
	while i <= #t do
		if t[i] < cutoff then table.remove(t, i) else i += 1 end
	end
end

local function updateRecord(record, payloadSize: number)
	local now = os.time()
	record.totalFires += 1
	record.lastFireTime = now
	table.insert(record.fireTimestamps, now)
	table.insert(record.payloadSizes, payloadSize)
	pruneTimestamps(record.fireTimestamps)
	if #record.payloadSizes > 100 then table.remove(record.payloadSizes, 1) end
	record.avgPayloadSize = avg(record.payloadSizes)
	record.avgFireRate = #record.fireTimestamps / SAMPLE_WINDOW
end

local function detectAnomalies(userId: number, record, payloadSize: number)
	local scorer = SuspicionScorer
	if not scorer then return end
	local profile = rawget(trafficProfiles, userId)
	if not profile then return end

	if not record.knownRemote then
		scorer.addManualScore(userId, 35, "UNKNOWN_REMOTE_FIRE", record.remotePath)
		profile.anomalyCount += 1
		return
	end

	if payloadSize > MAX_PAYLOAD_SIZE then
		scorer.addManualScore(userId, 20, "PAYLOAD_SIZE_EXCEEDED", record.remoteName .. ":" .. payloadSize)
		profile.anomalyCount += 1
	end

	if #record.payloadSizes >= MIN_SAMPLES then
		local a = record.avgPayloadSize
		local sd = stddev(record.payloadSizes, a)
		local z = sd > 0 and math.abs(payloadSize - a) / sd or 0
		if z > ANOMALY_Z_THRESHOLD and a > 10 then
			scorer.addManualScore(userId, 15, "PAYLOAD_SIZE_ANOMALY",
				string.format("%s z:%.1f avg:%.0f cur:%d", record.remoteName, z, a, payloadSize))
			profile.anomalyCount += 1
		end
	end

	if #record.fireTimestamps > Constants.MAX_BURST_REQUESTS then
		scorer.addManualScore(userId, 25, "REMOTE_BURST_FIRE", record.remoteName .. ":" .. #record.fireTimestamps)
		profile.anomalyCount += 1
	end

	if #record.fireTimestamps >= MIN_SAMPLES then
		local gaps = {}
		for i = 2, #record.fireTimestamps do
			table.insert(gaps, record.fireTimestamps[i] - record.fireTimestamps[i - 1])
		end
		local ga = avg(gaps)
		local gsd = stddev(gaps, ga)
		if ga > 0 and gsd / ga < 0.05 and #gaps >= 8 then
			scorer.addManualScore(userId, 20, "SCRIPTED_FIRE_PATTERN",
				string.format("%s gap:%.3fs sd:%.4f", record.remoteName, ga, gsd))
			profile.anomalyCount += 1
		end
	end
end

local function attachToRemote(remote: RemoteEvent, isKnown: boolean)
	if rawget(monitoredRemotes, remote) then return end
	rawset(monitoredRemotes, remote, true)
	remote.OnServerEvent:Connect(function(player, payload)
		if not player or not player:IsDescendantOf(Players) then return end
		local userId = player.UserId
		local payloadSize = estimateSize(payload)
		local profile = getOrCreateProfile(userId)
		profile.totalFires += 1
		local record = getOrCreateRecord(profile, remote.Name, remote:GetFullName(), isKnown)
		updateRecord(record, payloadSize)
		task.defer(detectAnomalies, userId, record, payloadSize)
	end)
end

local function scanAndAttach(root: Instance, isKnown: boolean)
	for _, descendant in ipairs(root:GetDescendants()) do
		if descendant:IsA("RemoteEvent") then
			attachToRemote(descendant :: RemoteEvent, isKnown)
		end
	end
	root.DescendantAdded:Connect(function(descendant)
		if descendant:IsA("RemoteEvent") then
			local known = isKnown and rawget(knownRemoteWhitelist, descendant:GetFullName()) ~= false
			attachToRemote(descendant :: RemoteEvent, known)
		end
	end)
end

function RemoteTrafficMonitor.whitelistRemote(path: string)
	rawset(knownRemoteWhitelist, path, true)
end

function RemoteTrafficMonitor.getProfile(userId: number)
	return rawget(trafficProfiles, userId)
end

function RemoteTrafficMonitor.getRemoteSummary(userId: number): { [string]: any }
	local profile = rawget(trafficProfiles, userId)
	if not profile then return {} end
	local summary = {}
	for name, record in pairs(profile.remotes) do
		summary[name] = {
			totalFires = record.totalFires,
			avgPayloadSize = math.floor(record.avgPayloadSize),
			avgFireRate = string.format("%.2f/min", record.avgFireRate * 60),
			knownRemote = record.knownRemote,
		}
	end
	return summary
end

function RemoteTrafficMonitor.init()
	if initialized then return end
	initialized = true

	local ok, sc = pcall(require, ServerScriptService:WaitForChild("RSF_Server"):WaitForChild("ValidationLayer"):WaitForChild("SuspicionScorer"))
	if ok then SuspicionScorer = sc end

	task.delay(3, function()
		local rsfRemotes = ReplicatedStorage:FindFirstChild("RSF_Remotes")
		if rsfRemotes then
			for _, child in ipairs(rsfRemotes:GetChildren()) do
				if child:IsA("RemoteEvent") then
					rawset(knownRemoteWhitelist, child:GetFullName(), true)
				end
			end
			scanAndAttach(rsfRemotes, true)
		end
		scanAndAttach(ReplicatedStorage, false)
		local ok2, ws = pcall(function() return game:GetService("Workspace") end)
		if ok2 and ws then scanAndAttach(ws, false) end
	end)

	Players.PlayerRemoving:Connect(function(player)
		task.delay(60, function() trafficProfiles[player.UserId] = nil end)
	end)
end

return RemoteTrafficMonitor
