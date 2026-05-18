local NetworkAnomalyDetector = {}

local Players = game:GetService("Players")
local ReplicatedStorage = game:GetService("ReplicatedStorage")
local ServerScriptService = game:GetService("ServerScriptService")

local Constants = require(ReplicatedStorage:WaitForChild("RSF_Shared"):WaitForChild("Constants"):WaitForChild("SecurityConstants"))

local SuspicionScorer
local ANALYSIS_WINDOW = 30
local MIN_SAMPLES = 8
local LAG_MULTIPLIER = 2.5
local CONSECUTIVE_ANOMALY_LIMIT = 4

local profiles: { [number]: {
	userId: number,
	pingHistory: { number },
	packetTimestamps: { number },
	burstCount: number,
	silenceStart: number?,
	consecutiveAnomalies: number,
	lastPacketTime: number,
	totalPackets: number,
	lagSpikes: number,
} } = {}

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

local function getOrCreate(userId: number)
	local p = rawget(profiles, userId)
	if p then return p end
	local profile = {
		userId = userId,
		pingHistory = {},
		packetTimestamps = {},
		burstCount = 0,
		silenceStart = nil,
		consecutiveAnomalies = 0,
		lastPacketTime = os.clock(),
		totalPackets = 0,
		lagSpikes = 0,
	}
	rawset(profiles, userId, profile)
	return profile
end

local function getPing(player: Player): number
	local ok, ping = pcall(function() return player:GetNetworkPing() * 1000 end)
	if ok and type(ping) == "number" and ping >= 0 then return ping end
	return -1
end

local function isLagActive(profile): boolean
	if #profile.pingHistory < 3 then return false end
	local recent = profile.pingHistory[#profile.pingHistory]
	local a = avg(profile.pingHistory)
	return recent > a * LAG_MULTIPLIER and recent > 300
end

local function recordPing(player: Player, profile)
	local ping = getPing(player)
	if ping < 0 then return end
	table.insert(profile.pingHistory, ping)
	if #profile.pingHistory > 20 then table.remove(profile.pingHistory, 1) end
	if #profile.pingHistory >= 3 then
		local a = avg(profile.pingHistory)
		local sd = stddev(profile.pingHistory, a)
		if ping > a + sd * 3 and ping > 500 then
			profile.lagSpikes += 1
		end
	end
end

local function pruneWindow(timestamps: { number })
	local cutoff = os.clock() - ANALYSIS_WINDOW
	local i = 1
	while i <= #timestamps do
		if timestamps[i] < cutoff then table.remove(timestamps, i) else i += 1 end
	end
end

local function analyzePacketRate(userId: number, profile)
	pruneWindow(profile.packetTimestamps)
	if #profile.packetTimestamps < MIN_SAMPLES then return end
	if isLagActive(profile) then return end

	local rate = #profile.packetTimestamps / ANALYSIS_WINDOW
	if rate > Constants.MAX_BURST_REQUESTS / Constants.BURST_WINDOW then
		profile.consecutiveAnomalies += 1
		profile.burstCount += 1
		if profile.consecutiveAnomalies >= CONSECUTIVE_ANOMALY_LIMIT and SuspicionScorer then
			SuspicionScorer.addManualScore(userId, 20, "NETWORK_BURST",
				string.format("rate:%.1f/s consecutive:%d", rate, profile.consecutiveAnomalies))
			profile.consecutiveAnomalies = 0
		end
		return
	end

	local gaps = {}
	for i = 2, #profile.packetTimestamps do
		table.insert(gaps, profile.packetTimestamps[i] - profile.packetTimestamps[i - 1])
	end
	local ga = avg(gaps)
	local gsd = stddev(gaps, ga)
	if ga > 0 and gsd / ga < 0.04 and #gaps >= 10 and SuspicionScorer then
		SuspicionScorer.addManualScore(userId, 18, "SCRIPTED_PACKET_TIMING",
			string.format("gap:%.3fs sd:%.4f", ga, gsd))
		return
	end

	profile.consecutiveAnomalies = math.max(0, profile.consecutiveAnomalies - 1)
end

local function analyzeSilence(userId: number, profile)
	local now = os.clock()
	local elapsed = now - profile.lastPacketTime
	if elapsed > 90 then
		if not profile.silenceStart then profile.silenceStart = now end
		local duration = now - (profile.silenceStart or now)
		if duration > 180 and SuspicionScorer then
			SuspicionScorer.addManualScore(userId, 10, "HEARTBEAT_SILENCE",
				string.format("silent:%.0fs", duration))
			profile.silenceStart = now
		end
	else
		profile.silenceStart = nil
	end
end

function NetworkAnomalyDetector.recordPacket(userId: number)
	local profile = getOrCreate(userId)
	local now = os.clock()
	profile.lastPacketTime = now
	profile.totalPackets += 1
	table.insert(profile.packetTimestamps, now)
	if #profile.packetTimestamps > 200 then table.remove(profile.packetTimestamps, 1) end
end

function NetworkAnomalyDetector.getSummary(userId: number): { [string]: any }
	local p = rawget(profiles, userId)
	if not p then return {} end
	local player = Players:GetPlayerByUserId(userId)
	return {
		totalPackets = p.totalPackets,
		burstCount = p.burstCount,
		lagSpikes = p.lagSpikes,
		consecutiveAnomalies = p.consecutiveAnomalies,
		currentPing = player and getPing(player) or -1,
		recentPackets = #p.packetTimestamps,
		avgPing = math.floor(avg(p.pingHistory)),
	}
end

function NetworkAnomalyDetector.init()
	if initialized then return end
	initialized = true

	local ok, sc = pcall(require, ServerScriptService:WaitForChild("RSF_Server"):WaitForChild("ValidationLayer"):WaitForChild("SuspicionScorer"))
	if ok then SuspicionScorer = sc end

	Players.PlayerAdded:Connect(function(player) getOrCreate(player.UserId) end)
	Players.PlayerRemoving:Connect(function(player)
		task.delay(60, function() profiles[player.UserId] = nil end)
	end)

	for _, player in ipairs(Players:GetPlayers()) do getOrCreate(player.UserId) end

	task.spawn(function()
		while initialized do
			task.wait(15)
			for userId, profile in pairs(profiles) do
				local player = Players:GetPlayerByUserId(userId)
				if not player then continue end
				task.spawn(function()
					recordPing(player, profile)
					analyzePacketRate(userId, profile)
					analyzeSilence(userId, profile)
				end)
			end
		end
	end)
end

function NetworkAnomalyDetector.getAllSummaries(): { [number]: { [string]: any } }
	local result = {}
	for userId, _ in pairs(profiles) do
		result[userId] = NetworkAnomalyDetector.getSummary(userId)
	end
	return result
end

function NetworkAnomalyDetector.reset(userId: number)
	local profile = rawget(profiles, userId)
	if not profile then return end
	profile.pingHistory = {}
	profile.packetTimestamps = {}
	profile.burstCount = 0
	profile.silenceStart = nil
	profile.consecutiveAnomalies = 0
	profile.lagSpikes = 0
	profile.totalPackets = 0
	profile.lastPacketTime = os.clock()
end

function NetworkAnomalyDetector.isActive(): boolean
	return initialized
end

return NetworkAnomalyDetector
