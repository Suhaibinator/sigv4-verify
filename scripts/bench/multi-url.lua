-- multi-url.lua — wrk script that replays a file of request lines round-robin.
--
-- Each line of URLS_FILE is "METHOD /path?query" (as produced by gen-urls.sh);
-- a bare "/path?query" defaults to GET. The Host header is taken from
-- BENCH_HOST so requests route to the correct NGINX server block.
--
-- Usage:
--   URLS_FILE=/tmp/urls.txt BENCH_HOST=assets.example.test \
--     wrk -t4 -c64 -d30s --latency -s scripts/bench/multi-url.lua \
--     http://127.0.0.1:8080

local requests = {}
local index = 0

local function trim(s)
    return (s:gsub("^%s*(.-)%s*$", "%1"))
end

function init(args)
    local path = os.getenv("URLS_FILE")
    if not path then
        error("URLS_FILE environment variable is required")
    end
    local host = os.getenv("BENCH_HOST")

    local file = assert(io.open(path, "r"))
    for raw in file:lines() do
        local line = trim(raw)
        if #line > 0 then
            local method, target = line:match("^(%S+)%s+(%S+)$")
            if not method then
                method, target = "GET", line
            end
            local headers = {}
            if host then
                headers["Host"] = host
            end
            requests[#requests + 1] = wrk.format(method, target, headers)
        end
    end
    file:close()

    if #requests == 0 then
        error("no request lines loaded from " .. path)
    end
    io.write(string.format("loaded %d request lines from %s\n", #requests, path))
end

function request()
    index = index + 1
    if index > #requests then
        index = 1
    end
    return requests[index]
end

-- Print the percentile summary the benchmark spec asks for, including p99.9,
-- which wrk's built-in --latency table omits.
function done(summary, latency, requests_stat)
    local function us(p)
        return latency:percentile(p) / 1000.0
    end
    io.write("\n--- latency percentiles (ms) ---\n")
    io.write(string.format("p50   %8.3f\n", us(50)))
    io.write(string.format("p90   %8.3f\n", us(90)))
    io.write(string.format("p99   %8.3f\n", us(99)))
    io.write(string.format("p99.9 %8.3f\n", us(99.9)))
    io.write(string.format("requests %d, errors (status>=400 not counted here)\n", summary.requests))
end
