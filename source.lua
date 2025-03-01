local successfulTests, failedTests, missingAliases, testsInProgress, cClosureCount, luaClosureCount = 0, 0, 0, 0, 0, 0

function cloneref(object) return object end

local function getEnvironmentVariable(path)
    local value = getfenv(0)
    while value ~= nil and path ~= "" do
        local name, nextPath = string.match(path, "^([^.]+)%.?(.*)$")
        value = value[name]
        path = nextPath
    end
    return value
end

local function checkFunctionExists(name)
    return getEnvironmentVariable(name) ~= nil
end

local function runTestCallback(callback, functionToTest, index)
    local func = functionToTest
    if index then
        func = functionToTest[index]
    end
    local success, message = pcall(callback)
    local closureType
    if func then
        if iscclosure then
            closureType = iscclosure(func) and "C closure" or "Lua closure"
            if iscclosure(func) then cClosureCount = cClosureCount + 1 else luaClosureCount = luaClosureCount + 1 end
        else
            local function isCClosure(f) return debug.info(f, 's') == "[C]" end
            closureType = isCClosure(func) and "C closure" or "Lua closure"
            if isCClosure(func) then cClosureCount = cClosureCount + 1 else luaClosureCount = luaClosureCount + 1 end
        end
    end
    return success, message, closureType
end

local function checkAliases(aliases)
    local undefinedAliases = {}
    for _, alias in ipairs(aliases) do
        if getEnvironmentVariable(alias) == nil then
            table.insert(undefinedAliases, alias)
        end
    end
    return undefinedAliases
end

local function logTestResult(name, success, message, closureType, undefinedAliases)
    if success then
        successfulTests = successfulTests + 1
        print("✅ " .. name .. (message and " • " .. message or "") .. (closureType and " - " .. closureType or ""))
    else
        failedTests = failedTests + 1
        warn("⛔ " .. name .. " failed: " .. message .. (closureType and " - " .. closureType or ""))
    end
    if #undefinedAliases > 0 then
        missingAliases = missingAliases + 1
        warn("⚠️ " .. table.concat(undefinedAliases, ", "))
    end
end

local function runExecutorTest(name, aliases, callback, functionToTest, index)
    testsInProgress = testsInProgress + 1
    task.spawn(function()
        if name == "script" then
            local success, message = pcall(function() return script ~= nil end)
            if message then
                local pass, fail = pcall(function()
                    assert(script.Parent == nil, "Source script should be parented to nil")
                end)
                if pass then
                    successfulTests = successfulTests + 1
                    print("✅ " .. name)
                else
                    failedTests = failedTests + 1
                    warn("⛔ " .. name .. " failed: " .. fail)
                end
            else
                failedTests = failedTests + 1
                warn("⛔ " .. name)
            end
            testsInProgress = testsInProgress - 1
            return
        elseif not callback then
            print("⏺️ " .. name)
        elseif not checkFunctionExists(name) then
            failedTests = failedTests + 1
            warn("⛔ " .. name)
        else
            local success, message, closureType = runTestCallback(callback, functionToTest, index)
            local undefinedAliases = checkAliases(aliases)
            logTestResult(name, success, message, closureType, undefinedAliases)
        end
        testsInProgress = testsInProgress - 1
    end)
end

local function shallowEqual(t1, t2)
    if t1 == t2 then return true end
    local uniqueTypes = { ["function"] = true, ["table"] = true, ["userdata"] = true, ["thread"] = true }
    for k, v in pairs(t1) do
        if uniqueTypes[type(v)] then
            if type(t2[k]) ~= type(v) then return false end
        elseif t2[k] ~= v then return false end
    end
    for k, v in pairs(t2) do
        if uniqueTypes[type(v)] then
            if type(t1[k]) ~= type(v) then return false end
        elseif t1[k] ~= v then return false end
    end
    return true
end

-- Initial output
print("UNC Env Check")
print("✅ - Pass, ⛔ - Fail, ⏺️ - No test, ⚠️ - Missing aliases\n")

-- Test result summary
task.defer(function()
    repeat task.wait() until testsInProgress == 0
    local totalTests = successfulTests + failedTests
    local successRate = totalTests > 0 and math.round(successfulTests / totalTests * 100) or 0
    local outOf = successfulTests .. " out of " .. totalTests
    local totalClosures = cClosureCount + luaClosureCount
    local cClosurePercent = totalClosures > 0 and math.round(cClosureCount / totalClosures * 100) or 0
    local luaClosurePercent = totalClosures > 0 and math.round(luaClosureCount / totalClosures * 100) or 0
    print("UNC Test Result")
    print("✅ Completed all tests with a " .. successRate .. "% success rate (" .. outOf .. ")")
    print("⛔ " .. failedTests .. " function tests failed")
    print("⚠️ " .. missingAliases .. " function globals are missing aliases")
    print("ℹ️ " .. cClosurePercent .. "% of functions are C closures")
    print("ℹ️ " .. luaClosurePercent .. "% of functions are Lua closures")
    print("Build: 030125162 | Credit: sharpcystals")
end)

-- Cache Tests
local function runCacheTests()
    runExecutorTest("cache.clone", {}, function()
        local originalPart = Instance.new("Part")
        local function testFunction() return "success" end
        local clonedFunction = cache.clone(testFunction)
        local clonedPart = cache.clone(originalPart)
        assert(originalPart ~= clonedPart, "Cloned instance should not equal original")
        assert(not ({[originalPart] = false})[clonedPart], "Cloned instance should not be in original's table")
        clonedPart.Name = "Test"
        assert(originalPart.Name == "Test", "Cloned instance should update original")
        assert(testFunction() == clonedFunction(), "Cloned function should match original output")
        assert(testFunction ~= clonedFunction, "Cloned function should not equal original")
    end, cache, 'clone')

    runExecutorTest("cache.compare", {}, function()
        local originalPart = Instance.new("Part")
        local clonedPart = cache.clone(originalPart)
        assert(originalPart ~= clonedPart, "Clone should not equal original")
        assert(cache.compare(originalPart, clonedPart), "cache.compare should equate clone with original")
    end, cache, 'compare')

    runExecutorTest("cache.invalidate", {}, function()
        local container = Instance.new("Folder")
        local part = Instance.new("Part", container)
        cache.invalidate(container:FindFirstChild("Part"))
        assert(part ~= container:FindFirstChild("Part"), "Part reference could not be invalidated")
    end, cache, 'invalidate')

    runExecutorTest("cache.iscached", {"cache.cached"}, function()
        local part = Instance.new("Part")
        assert(cache.iscached(part), "Part should be cached initially")
        cache.invalidate(part)
        assert(not cache.iscached(part), "Part should not be cached after invalidation")
    end, cache, 'iscached')

    runExecutorTest("cache.replace", {}, function()
        local part = Instance.new("Part")
        local fire = Instance.new("Fire")
        cache.replace(part, fire)
        assert(part ~= fire, "Part should be replaced with Fire")
    end, cache, 'replace')
end

-- Closure Tests
local function runClosureTests()
    runExecutorTest("cloneref", {"clonereference"}, function()
        local originalPart = Instance.new("Part")
        local clonedPart = cloneref(originalPart)
        assert(originalPart ~= clonedPart, "Clone should not equal original")
        clonedPart.Name = "Test"
        assert(originalPart.Name == "Test", "Clone should update original")
        assert(typeof(clonedPart) == typeof(originalPart), "Clone type should match original")
    end, cloneref)

    runExecutorTest("compareinstances", {}, function()
        local originalPart = Instance.new("Part")
        local clonedPart = cloneref(originalPart)
        assert(originalPart ~= clonedPart, "Clone should not equal original")
        assert(compareinstances(originalPart, clonedPart), "compareinstances should equate clone with original")
    end, compareinstances)

    runExecutorTest("checkcaller", {}, function()
        assert(checkcaller(), "Main scope should return true")
    end, checkcaller)

    runExecutorTest("clonefunction", {}, function()
        local function testFunction() return "success" end
        local clonedFunction = clonefunction(testFunction)
        assert(testFunction() == clonedFunction(), "Clone should match original output")
        assert(testFunction ~= clonedFunction, "Clone should not equal original")
    end, clonefunction)

    runExecutorTest("getcallingscript", {"getcaller"}, function()
        assert(getcallingscript() == script, "Caller should be current script")
    end, getcallingscript)

    runExecutorTest("getscriptclosure", {"getscriptfunction"}, function()
        local module = game:GetService("CoreGui").RobloxGui.Modules.Common.Constants
        local constants = getrenv().require(module)
        local generated = getscriptclosure(module)()
        assert(constants ~= generated, "Generated module should not equal original")
        assert(shallowEqual(constants, generated), "Generated constants should be shallow equal to original")
    end, getscriptclosure)

    runExecutorTest("hookfunction", {"replaceclosure"}, function()
        local function testFunction() return true end
        local original = hookfunction(testFunction, function() return false end)
        assert(testFunction() == false, "Hooked function should return false")
        assert(original() == true, "Original function should return true")
        assert(testFunction ~= original, "Hooked function should not equal original")
    end, hookfunction)

    runExecutorTest("hooksignal", {"replacecon"}, function()
        local part = Instance.new("Part")
        local changedProperty
        part.Changed:Connect(function(prop) changedProperty = prop end)
        hooksignal(part.Changed, function(info, prop) return true, "Hooked" end)
        part.Name = "NewName"
        assert(changedProperty == "Hooked", "Signal should be hooked")
    end, hooksignal)

    runExecutorTest("iscclosure", {}, function()
        assert(iscclosure(print) == true, "'print' should be a C closure")
        assert(iscclosure(function() end) == false, "Anonymous function should not be a C closure")
    end, iscclosure)

    runExecutorTest("isfunctionhooked", {}, function()
        local function testFunction() return true end
        hookfunction(testFunction, function() return false end)
        assert(isfunctionhooked(testFunction), "Function should be marked as hooked")
    end, isfunctionhooked)

    runExecutorTest("issignalhooked", {}, function()
        local part = Instance.new("Part")
        local changedProperty
        part.Changed:Connect(function(prop) changedProperty = prop end)
        hooksignal(part.Changed, function(info, prop) return true, "Hooked" end)
        part.Name = "NewName"
        assert(issignalhooked(part.Changed), "Signal should be marked as hooked")
    end, issignalhooked)

    runExecutorTest("islclosure", {}, function()
        assert(islclosure(print) == false, "'print' should not be a Lua closure")
        assert(islclosure(function() end) == true, "Anonymous function should be a Lua closure")
    end, islclosure)

    runExecutorTest("isexecutorclosure", {"checkclosure", "isourclosure", "isexploitclosure"}, function()
        assert(isexecutorclosure(isexecutorclosure) == true, "Executor global should return true")
        assert(isexecutorclosure(newcclosure(function() end)) == true, "Executor C closure should return true")
        assert(isexecutorclosure(function() end) == true, "Executor Lua closure should return true")
        assert(isexecutorclosure(print) == false, "Roblox global should return false")
    end, isexecutorclosure)

    runExecutorTest("loadstring", {}, function()
        if getscriptbytecode then
            local animate = game:GetService("Players").LocalPlayer.Character.Animate
            local bytecode = getscriptbytecode(animate)
            local func = loadstring(bytecode)
            assert(type(func) ~= "function", "Luau bytecode should not be loadable")
            assert(loadstring("return ... + 1")(1) == 2, "loadstring failed to load Lua code")
            assert(type(select(2, loadstring("f"))) == "string", "loadstring should return error for invalid code")
        else
            local func = loadstring("getgenv().UNCtest = 1")
            assert(type(func) == "function", "loadstring did not return a function")
            local success, err = pcall(func)
            assert(success, "loadstring failed to execute: " .. (err or "unknown error"))
            assert(getgenv().UNCtest, "loadstring did not set global")
            getgenv().UNCtest = nil
        end
    end, loadstring)

    runExecutorTest("newcclosure", {}, function()
        local function testFunction() return true end
        local cClosure = newcclosure(testFunction)
        assert(testFunction() == cClosure(), "C closure should match original output")
        assert(testFunction ~= cClosure, "C closure should not equal original")
        assert(iscclosure(cClosure), "Should be a C closure")
    end, newcclosure)

    runExecutorTest("restorefunction", {}, function()
        local originalVersion = version
        version = function() end
        task.defer(function() getfenv().version = originalVersion end)
        assert(version ~= originalVersion, "Function tampering failed")
        restorefunction(version)
        assert(version == originalVersion, "Function not restored")
    end, restorefunction)

    runExecutorTest("restoresignal", {}, function()
        local part = Instance.new("Part")
        local changedProperty
        part.Changed:Connect(function(prop) changedProperty = prop end)
        hooksignal(part.Changed, function(info, prop) return true, "Hooked" end)
        part.Name = "NewName"
        assert(changedProperty == "Hooked", "Signal should be hooked")
        restoresignal(part.Changed)
        part.Name = "NewName2"
        assert(changedProperty ~= "Hooked", "Signal should not be hooked after restore")
        assert(not issignalhooked(part.Changed), "Signal should not be marked as hooked")
    end, restoresignal)
end

-- Crypt Tests
local function runCryptTests()
    runExecutorTest("crypt.base64encode", {"crypt.base64.encode", "crypt.base64_encode", "base64.encode", "base64_encode"}, function()
        assert(crypt.base64encode("test") == "dGVzdA==", "Base64 encoding failed for 'test'")
        assert(crypt.base64encode("hello") == "aGVsbG8=", "Base64 encoding failed for 'hello'")
    end, crypt, 'base64encode')

    runExecutorTest("crypt.base64decode", {"crypt.base64.decode", "crypt.base64_decode", "base64.decode", "base64_decode"}, function()
        assert(crypt.base64decode("dGVzdA==") == "test", "Base64 decoding failed for 'test'")
        assert(crypt.base64decode("aGVsbG8=") == "hello", "Base64 decoding failed for 'hello'")
    end, crypt, 'base64decode')

    runExecutorTest("crypt.encrypt", {}, function()
        local key = crypt.generatekey()
        local encrypted, iv = crypt.encrypt("test", key, nil, "CBC")
        assert(iv, "IV should be returned")
        local decrypted = crypt.decrypt(encrypted, key, iv, "CBC")
        assert(decrypted == "test", "Decryption failed")
    end, crypt, 'encrypt')

    runExecutorTest("crypt.decrypt", {}, function()
        local key, iv = crypt.generatekey(), crypt.generatekey()
        local encrypted = crypt.encrypt("test", key, iv, "CBC")
        local decrypted = crypt.decrypt(encrypted, key, iv, "CBC")
        assert(decrypted == "test", "Decryption failed")
    end, crypt, 'decrypt')

    runExecutorTest("crypt.generatebytes", {}, function()
        local size = math.random(10, 100)
        local bytes = crypt.generatebytes(size)
        assert(#crypt.base64decode(bytes) == size, "Generated bytes length mismatch")
    end, crypt, 'generatebytes')

    runExecutorTest("crypt.generatekey", {}, function()
        local key = crypt.generatekey()
        assert(#crypt.base64decode(key) == 32, "Key should be 32 bytes when decoded")
    end, crypt, 'generatekey')

    runExecutorTest("crypt.hash", {}, function()
        local algorithms = {'sha1', 'sha384', 'sha512', 'md5', 'sha256', 'sha3-224', 'sha3-256', 'sha3-512'}
        for _, algo in ipairs(algorithms) do
            assert(crypt.hash("test", algo), "Hash failed for " .. algo)
        end
    end, crypt, 'hash')
end

-- Debug Tests
local function runDebugTests()
    runExecutorTest("debug.getconstant", {"getconstant", "getconst", "debug.getconst"}, function()
        local function testFunction() print("Hello, world!") end
        assert(debug.getconstant(testFunction, 1) == "print", "First constant should be 'print'")
        assert(debug.getconstant(testFunction, 2) == nil, "Second constant should be nil")
        assert(debug.getconstant(testFunction, 3) == "Hello, world!", "Third constant should be 'Hello, world!'")
        if debug.getconstants then
            assert(not pcall(function() debug.getconstant(testFunction, #debug.getconstants(testFunction) + 1) end), "Should check bounds")
        end
    end, debug, 'getconstant')

    runExecutorTest("debug.getconstants", {"getconstants", "getconsts", "debug.getconsts"}, function()
        local function testFunction() local num = 5000 .. 50000; print("Hello, world!", num, warn) end
        local constants = debug.getconstants(testFunction)
        assert(constants[1] == 50000, "First constant should be 50000")
        assert(constants[2] == "print", "Second constant should be 'print'")
    end, debug, 'getconstants')

    runExecutorTest("debug.getinfo", {"debug.getfunctioninfo", "debug.getfuncinfo"}, function()
        local function testFunction(...) print(...) end
        local info = debug.getinfo(testFunction)
        local expectedTypes = {source = "string", short_src = "string", func = "function", what = "string", currentline = "number", name = "string", nups = "number", numparams = "number", is_vararg = "number"}
        for k, v in pairs(expectedTypes) do
            assert(info[k] ~= nil and type(info[k]) == v, "Field " .. k .. " should be " .. v)
        end
    end, debug, 'getinfo')

    runExecutorTest("debug.getmetatable", {"getrawmetatable"}, function()
        local metatable = {__metatable = "Locked!"}
        local object = setmetatable({}, metatable)
        assert(debug.getmetatable(object) == metatable, "Should return raw metatable")
    end, debug, 'getmetatable')

    runExecutorTest("debug.getproto", {"getproto"}, function()
        local function testFunction() local function proto() return true end end
        local proto = debug.getproto(testFunction, 1, true)[1]
        assert(proto and proto() == true, "Should get and call inner function")
    end, debug, 'getproto')

    runExecutorTest("debug.getprotos", {"getprotos"}, function()
        local function testFunction() local function p1() return true end local function p2() return true end end
        local protos = debug.getprotos(testFunction)
        assert(#protos == 2, "Should return two prototypes")
    end, debug, 'getprotos')

    runExecutorTest("debug.getregistry", {"getregistry", "getreg", "debug.getreg"}, function()
        local registry = debug.getregistry()
        assert(type(registry) == "table" and #registry > 0, "Should return non-empty table")
    end, debug, 'getregistry')

    runExecutorTest("debug.getregistery", {"getregistery"}, function()
        local registry = debug.getregistery()
        assert(type(registry) == "table" and #registry > 0, "Should return non-empty table")
    end, debug, 'getregistery')

    runExecutorTest("debug.setmetatable", {"setrawmetatable"}, function()
        local object = setmetatable({}, {__index = function() return false end, __metatable = "Locked!"})
        debug.setmetatable(object, {__index = function() return true end})
        assert(object.test == true, "Should update metatable")
    end, debug, 'setmetatable')

    runExecutorTest("debug.getstack", {}, function()
        local _ = "a" .. "b"
        assert(debug.getstack(1, 1) == "ab", "First stack item should be 'ab'")
    end, debug, 'getstack')

    runExecutorTest("debug.getupvalue", {"getupvalue", "getupval"}, function()
        local upvalue = function() end
        local function testFunction() print(upvalue) end
        assert(debug.getupvalue(testFunction, 1) == upvalue, "Should get upvalue")
    end, debug, 'getupvalue')

    runExecutorTest("debug.getupvalues", {"getupvalues", "getupvals", "debug.getupvals"}, function()
        local upvalue = function() end
        local function testFunction() print(upvalue) end
        assert(debug.getupvalues(testFunction)[1] == upvalue, "Should get upvalues")
    end, debug, 'getupvalues')

    runExecutorTest("debug.setconstant", {"setconst", "setconstants", "debug.setconstants", "debug.setconsts"}, function()
        local function testFunction() return "fail" end
        debug.setconstant(testFunction, 1, "success")
        assert(testFunction() == "success", "Should set constant")
    end, debug, 'setconstant')

    runExecutorTest("debug.setstack", {}, function()
        local function testFunction() return "fail", debug.setstack(1, 1, "success") end
        assert(testFunction() == "success", "Should set stack value")
    end, debug, 'setstack')

    runExecutorTest("debug.setupvalue", {"setupvalue", "setupvals", "setupval", "debug.setupval", "debug.setupvals"}, function()
        local function upvalue() return "fail" end
        local function testFunction() return upvalue() end
        debug.setupvalue(testFunction, 1, function() return "success" end)
        assert(testFunction() == "success", "Should set upvalue")
    end, debug, 'setupvalue')
end

-- Drawing Tests
local function runDrawingTests()
    runExecutorTest("cleardrawcache", {}, function()
        local drawing = Drawing.new("Circle")
        drawing.Visible = false
        cleardrawcache()
        assert(drawing == nil, "Should clear drawing cache")
    end, cleardrawcache)

    runExecutorTest("Drawing.clear", {}, function()
        local drawing = Drawing.new("Image")
        drawing.Visible = false
        Drawing.clear()
    end, Drawing, 'clear')

    runExecutorTest("Drawing.Fonts", {}, function()
        assert(Drawing.Fonts.UI == 0, "UI font ID incorrect")
        assert(Drawing.Fonts.System == 1, "System font ID incorrect")
        assert(Drawing.Fonts.Plex == 2, "Plex font ID incorrect")
        assert(Drawing.Fonts.Monospace == 3, "Monospace font ID incorrect")
    end)

    runExecutorTest("Drawing.new", {}, function()
        local drawing = Drawing.new("Square")
        drawing.Visible = false
        assert(pcall(function() drawing:Destroy() end), "Destroy should not error")
    end, Drawing, 'new')

    runExecutorTest("getrenderproperty", {}, function()
        local drawing = Drawing.new("Image")
        drawing.Visible = true
        assert(type(getrenderproperty(drawing, "Visible")) == "boolean", "Visible should be boolean")
    end, getrenderproperty)

    runExecutorTest("isrenderobj", {}, function()
        local drawing = Drawing.new("Image")
        assert(isrenderobj(drawing) == true, "Should recognize drawing object")
        assert(isrenderobj(newproxy()) == false, "Should not recognize proxy")
    end, isrenderobj)

    runExecutorTest("setrenderproperty", {}, function()
        local drawing = Drawing.new("Square")
        drawing.Visible = true
        setrenderproperty(drawing, "Visible", false)
        assert(drawing.Visible == false, "Should set Visible to false")
    end, setrenderproperty)
end

-- Filesystem Tests
local function runFilesystemTests()
    if isfolder and makefolder and delfolder then
        if isfolder(".tests") then delfolder(".tests") end
        makefolder(".tests")
    end

    runExecutorTest("appendfile", {}, function()
        writefile(".tests/appendfile.txt", "su")
        appendfile(".tests/appendfile.txt", "cce")
        appendfile(".tests/appendfile.txt", "ss")
        assert(readfile(".tests/appendfile.txt") == "success", "File append failed")
    end, appendfile)

    runExecutorTest("delfile", {}, function()
        writefile(".tests/delfile.txt", "Hello, world!")
        delfile(".tests/delfile.txt")
        assert(not isfile(".tests/delfile.txt"), "File deletion failed")
    end, delfile)

    runExecutorTest("delfolder", {}, function()
        makefolder(".tests/delfolder")
        delfolder(".tests/delfolder")
        assert(not isfolder(".tests/delfolder"), "Folder deletion failed")
    end, delfolder)

    runExecutorTest("isfile", {}, function()
        writefile(".tests/isfile.txt", "success")
        assert(isfile(".tests/isfile.txt"), "Should recognize file")
        assert(not isfile(".tests"), "Should not recognize folder as file")
    end, isfile)

    runExecutorTest("isfolder", {}, function()
        assert(isfolder(".tests"), "Should recognize folder")
        assert(not isfolder(".tests/doesnotexist.exe"), "Should not recognize nonexistent path")
    end, isfolder)

    runExecutorTest("listfiles", {}, function()
        makefolder(".tests/listfiles")
        writefile(".tests/listfiles/test_1.txt", "success")
        writefile(".tests/listfiles/test_2.txt", "success")
        local files = listfiles(".tests/listfiles")
        assert(#files == 2, "Should list two files")
        assert(isfile(files[1]), "Should return file paths")
    end, listfiles)

    runExecutorTest("loadfile", {}, function()
        writefile(".tests/loadfile.txt", "return ... + 1")
        assert(loadfile(".tests/loadfile.txt")(1) == 2, "Loadfile execution failed")
    end, loadfile)

    runExecutorTest("makefolder", {}, function()
        makefolder(".tests/makefolder")
        assert(isfolder(".tests/makefolder"), "Folder creation failed")
    end, makefolder)

    runExecutorTest("readfile", {}, function()
        writefile(".tests/readfile.txt", "success")
        assert(readfile(".tests/readfile.txt") == "success", "File read failed")
    end, readfile)

    runExecutorTest("writefile", {}, function()
        writefile(".tests/writefile.txt", "success")
        assert(readfile(".tests/writefile.txt") == "success", "File write failed")
    end, writefile)
end

-- Instance Tests
local function runInstanceTests()
    runExecutorTest("filtergc", {}, function()
        local tbl = {UNC = "Testing"}
        local metatable = {__idiv = function() return 0.1515 end, __div = function() return "Ballers" end, __metatable = "Locked"}
        setmetatable({}, metatable)
        local filtered = filtergc("table", {KeyValuePairs = tbl, Keys = {"UNC"}, Values = {"Testing"}, Metatable = metatable})
        assert(#filtered > 0 and filtered[1] == tbl, "Should filter table correctly")
    end, filtergc)

    runExecutorTest("fireclickdetector", {}, function()
        local done = false
        local detector = Instance.new("ClickDetector")
        detector.MouseClick:Connect(function() done = true end)
        fireclickdetector(detector, 1, "MouseClick")
        assert(done, "Click detector not fired")
    end, fireclickdetector)

    runExecutorTest("fireproximityprompt", {}, function()
        local prompt = Instance.new("ProximityPrompt")
        fireproximityprompt(prompt)
    end, fireproximityprompt)

    runExecutorTest("firesignal", {}, function()
        local event = Instance.new("BindableEvent")
        local result = false
        event.Event:Connect(function(arg) result = arg end)
        firesignal(event.Event, true)
        assert(result, "Signal not fired")
    end, firesignal)

    runExecutorTest("firetouchinterest", {}, function()
        local done, count = false, 0
        local part = Instance.new("Part", game:GetService("Workspace"))
        part.Touched:Connect(function() done = true; count = count + 1 end)
        firetouchinterest(part, game:GetService("Players").LocalPlayer.Character.PrimaryPart, 0)
        task.wait()
        firetouchinterest(part, game:GetService("Players").LocalPlayer.Character.PrimaryPart, 1)
        assert(done and count == 1, "Touch interest failed")
        part:Destroy()
    end, firetouchinterest)

    runExecutorTest("getcacheinstances", {}, function()
        assert(getcacheinstances()[1]:IsA("Instance"), "Should return Instances")
    end, getcacheinstances)

    runExecutorTest("getcallbackvalue", {}, function()
        local bindable = Instance.new("BindableFunction")
        local function test() end
        bindable.OnInvoke = test
        assert(getcallbackvalue(bindable, "OnInvoke") == test, "Callback value incorrect")
    end, getcallbackvalue)

    runExecutorTest("getconnections", {}, function()
        local bindable = Instance.new("BindableEvent")
        bindable.Event:Connect(function() end)
        local conn = getconnections(bindable.Event)[1]
        local expectedTypes = {Enabled = "boolean", Fire = "function", Disconnect = "function"}
        for k, v in pairs(expectedTypes) do
            assert(conn[k] ~= nil and type(conn[k]) == v, "Connection field " .. k .. " incorrect")
        end
    end, getconnections)

    runExecutorTest("getcustomasset", {}, function()
        writefile(".tests/getcustomasset.txt", "success")
        local contentId = getcustomasset(".tests/getcustomasset.txt")
        assert(type(contentId) == "string" and string.match(contentId, "rbxasset://"), "Should return rbxasset URL")
    end, getcustomasset)

    runExecutorTest("gethiddenproperty", {}, function()
        local fire = Instance.new("Fire")
        local value, isHidden = gethiddenproperty(fire, "size_xml")
        assert(value == 5 and isHidden, "Hidden property incorrect")
    end, gethiddenproperty)

    runExecutorTest("gethui", {}, function()
        local hui = gethui()
        assert(hui == game:GetService("CoreGui") or hui == game:GetService("Players").LocalPlayer.PlayerGui, "Should return CoreGui or PlayerGui")
    end, gethui)

    runExecutorTest("getinstances", {}, function()
        assert(getinstances()[1]:IsA("Instance"), "Should return Instances")
    end, getinstances)

    runExecutorTest("getnamecallmethod", {"getncm", "get_namecall_method"}, function()
        pcall(function() game:NAMECALL_TEST() end)
        assert(getnamecallmethod() == "NAMECALL_TEST", "Namecall method incorrect")
    end, getnamecallmethod)

    runExecutorTest("getnilinstances", {}, function()
        local inst = getnilinstances()[1]
        assert(inst:IsA("Instance") and inst.Parent == nil, "Should return nil-parented Instances")
    end, getnilinstances)

    runExecutorTest("getproperties", {"getprops"}, function()
        local part = Instance.new("Part")
        local props = getproperties(part)
        assert(props.Position ~= part.Position, "Properties should differ from instance")
    end, getproperties)

    runExecutorTest("isscriptable", {}, function()
        local fire = Instance.new("Fire")
        assert(not isscriptable(fire, "size_xml") and isscriptable(fire, "Size"), "Scriptable check failed")
    end, isscriptable)

    runExecutorTest("sethiddenproperty", {}, function()
        local fire = Instance.new("Fire")
        assert(sethiddenproperty(fire, "size_xml", 10) and gethiddenproperty(fire, "size_xml") == 10, "Hidden property set failed")
    end, sethiddenproperty)

    runExecutorTest("setnamecallmethod", {"setncm", "set_namecall_method"}, function()
        setnamecallmethod("GetService")
        local success = pcall(getrawmetatable(game).__namecall, game, "Workspace")
        assert(success, "Namecall method not set correctly")
    end, setnamecallmethod)

    runExecutorTest("setscriptable", {}, function()
        local fire = Instance.new("Fire")
        assert(not setscriptable(fire, "size_xml", true) and isscriptable(fire, "size_xml"), "Scriptable set failed")
    end, setscriptable)
end

-- Metatable Tests
local function runMetatableTests()
    runExecutorTest("getrawmetatable", {}, function()
        local metatable = {__metatable = "Locked!"}
        local object = setmetatable({}, metatable)
        assert(getrawmetatable(object) == metatable, "Raw metatable incorrect")
    end, getrawmetatable)

    runExecutorTest("hookmetamethod", {}, function()
        local object = setmetatable({}, {__index = newcclosure(function() return false end), __metatable = "Locked!"})
        local original = hookmetamethod(object, "__index", function() return true end)
        assert(object.test == true and original() == false, "Metamethod hook failed")
    end, hookmetamethod)

    runExecutorTest("isreadonly", {}, function()
        local tbl = table.freeze({})
        assert(isreadonly(tbl), "Should recognize read-only table")
    end, isreadonly)

    runExecutorTest("setrawmetatable", {}, function()
        local object = setmetatable({}, {__index = function() return false end, __metatable = "Locked!"})
        setrawmetatable(object, {__index = function() return true end})
        assert(object.test == true, "Raw metatable set failed")
    end, setrawmetatable)

    runExecutorTest("setreadonly", {}, function()
        local tbl = {success = false}
        table.freeze(tbl)
        setreadonly(tbl, false)
        tbl.success = true
        assert(tbl.success, "Table should be modifiable")
    end, setreadonly)
end

-- Miscellaneous Tests
local function runMiscTests()
    runExecutorTest("getclipboard", {"getrbxclipboard"}, function()
        assert(getclipboard() == "UNC", "Clipboard value incorrect")
    end, getclipboard)

    runExecutorTest("getfpscap", {}, function()
        assert(getfpscap() == 20, "FPS cap incorrect")
        setfpscap(60)
    end, getfpscap)

    runExecutorTest("gethwid", {"get_hwid"}, function()
        assert(type(gethwid()) == "string", "HWID should be string")
    end, gethwid)

    runExecutorTest("identifyexecutor", {"getexecutorname"}, function()
        local name, _ = identifyexecutor()
        assert(type(name) == "string", "Executor name should be string")
    end, identifyexecutor)

    runExecutorTest("isnetworkowner", {"isowner"}, function()
        assert(isnetworkowner(game:GetService("Players").LocalPlayer.Character.HumanoidRootPart), "Should own network")
    end, isnetworkowner)

    runExecutorTest("isrbxactive", {"isgameactive"}, function()
        assert(type(isrbxactive()) == "boolean", "Should return boolean")
    end, isrbxactive)

    runExecutorTest("lz4compress", {}, function()
        local raw = "Hello, world!"
        local compressed = lz4compress(raw)
        assert(lz4decompress(compressed, #raw) == raw, "Compression/decompression failed")
    end, lz4compress)

    runExecutorTest("lz4decompress", {}, function()
        local raw = "Hello, world!"
        local compressed = lz4compress(raw)
        assert(lz4decompress(compressed, #raw) == raw, "Decompression failed")
    end, lz4decompress)

    runExecutorTest("printidentity", {}, function()
        local conn, identity
        conn = game:GetService("LogService").MessageOut:Connect(function(msg)
            if msg:find("Current identity is") then identity = tonumber(msg:match("%d+")) end
        end)
        printidentity()
        repeat task.wait() until identity
        conn:Disconnect()
        assert(identity <= 9, "Identity should not exceed 9")
    end, printidentity)

    runExecutorTest("setclipboard", {"setrbxclipboard", "toclipboard"}, function()
        setclipboard("UNC")
    end, setclipboard)

    runExecutorTest("secure_call", {}, function()
        assert(not pcall(secure_call, "hello = nil"), "Should only accept functions")
    end, secure_call)

    runExecutorTest("setfpscap", {}, function()
        setfpscap(60)
    end, setfpscap)

    runExecutorTest("request", {"http.request", "http_request"}, function()
        local response = request({Url = "https://httpbin.org/user-agent", Method = "GET"})
        assert(response.StatusCode == 200, "Request failed")
    end, request)
end

-- Script Tests
local function runScriptTests()
    runExecutorTest("getallthreads", {"getthreads"}, function()
        local threads = getallthreads()
        assert(type(threads) == "table" and #threads > 0 and type(threads[1]) == "thread", "Should return threads")
    end, getallthreads)

    runExecutorTest("getgc", {"getgarbagecollector"}, function()
        local gc = getgc()
        assert(type(gc) == "table" and #gc > 0, "Should return non-empty table")
    end, getgc)

    runExecutorTest("getgenv", {}, function()
        getgenv().__TEST = true
        assert(__TEST, "Global set failed")
        getgenv().__TEST = nil
    end, getgenv)

    runExecutorTest("getloadedmodules", {}, function()
        local modules = getloadedmodules()
        assert(type(modules) == "table" and #modules > 0 and modules[1]:IsA("ModuleScript"), "Should return ModuleScripts")
    end, getloadedmodules)

    runExecutorTest("getrenv", {}, function()
        assert(_G ~= getrenv()._G, "Executor _G should differ from game _G")
    end, getrenv)

    runExecutorTest("getrunningscripts", {}, function()
        local scripts = getrunningscripts()
        assert(type(scripts) == "table" and #scripts > 0 and (scripts[1]:IsA("ModuleScript") or scripts[1]:IsA("LocalScript")), "Should return running scripts")
    end, getrunningscripts)

    runExecutorTest("getscriptbytecode", {"dumpstring"}, function()
        local bytecode = getscriptbytecode(game:GetService("Players").LocalPlayer.Character.Animate)
        assert(type(bytecode) == "string", "Bytecode should be string")
    end, getscriptbytecode)

    runExecutorTest("getscripthash", {}, function()
        local animate = game:GetService("Players").LocalPlayer.Character.Animate:Clone()
        local hash = getscripthash(animate)
        animate.Source = "print('Hello')"
        local newHash = getscripthash(animate)
        assert(hash ~= newHash, "Hash should change with source")
    end, getscripthash)

    runExecutorTest("getscripts", {}, function()
        local scripts = getscripts()
        assert(type(scripts) == "table" and #scripts > 0 and (scripts[1]:IsA("ModuleScript") or scripts[1]:IsA("LocalScript")), "Should return scripts")
    end, getscripts)

    runExecutorTest("getsenv", {}, function()
        local env = getsenv(game:GetService("Players").LocalPlayer.Character.Animate)
        assert(type(env) == "table" and env.script == game:GetService("Players").LocalPlayer.Character.Animate, "Should return script env")
    end, getsenv)

    runExecutorTest("gettenv", {}, function()
        local thread = task.defer(function() end)
        local env = gettenv(thread)
        assert(type(env) == "table", "Should return thread env")
    end, gettenv)

    runExecutorTest("getscriptthread", {}, function()
        assert(type(getscriptthread(game:GetService("Players").LocalPlayer.Character.Animate)) == "thread", "Should return thread")
    end, getscriptthread)

    runExecutorTest("getthreadidentity", {"getidentity", "getthreadcontext", "get_thread_identity"}, function()
        assert(type(getthreadidentity()) == "number", "Should return number")
    end, getthreadidentity)

    runExecutorTest("setthreadidentity", {"setidentity", "setthreadcontext", "set_thread_identity"}, function()
        setthreadidentity(3)
        assert(getthreadidentity() == 3, "Thread identity set failed")
    end, setthreadidentity)
end

-- Table Tests
local function runTableTests()
    runExecutorTest("table.freeze", {"freeze"}, function()
        local original = {{}}
        local frozen = table.freeze(original)
        assert(original == frozen and not pcall(function() original[1] = {} end) and not pcall(function() original[1][1] = {} end), "Freeze failed")
    end, table, 'freeze')

    runExecutorTest("table.isfrozen", {"isfrozen"}, function()
        local frozen = table.freeze({})
        assert(table.isfrozen(frozen) and not table.isfrozen({}), "Isfrozen check failed")
    end, table, 'isfrozen')

    runExecutorTest("table.unfreeze", {"unfreeze"}, function()
        local frozen = table.freeze({})
        local unfrozen = table.unfreeze(frozen)
        assert(unfrozen == frozen, "Unfreeze failed")
    end, table, 'unfreeze')
end

-- WebSocket Tests
local function runWebSocketTests()
    runExecutorTest("WebSocket.connect", {}, function()
        local wsc = WebSocket.connect("ws://echo.websocket.events")
        local expectedTypes = {Send = "function", Close = "function", OnMessage = {"table", "userdata"}, OnClose = {"table", "userdata"}}
        assert(type(wsc) == "table" or type(wsc) == "userdata", "Should return table or userdata")
        for k, v in pairs(expectedTypes) do
            if type(v) == "table" then
                assert(table.find(v, type(wsc[k])), "Field " .. k .. " type incorrect")
            else
                assert(type(wsc[k]) == v, "Field " .. k .. " should be " .. v)
            end
        end
    end, WebSocket, 'connect')
end

local function runAllTests()
    runCacheTests()
    runClosureTests()
    runCryptTests()
    runDebugTests()
    runDrawingTests()
    runFilesystemTests()
    runInstanceTests()
    runMetatableTests()
    runMiscTests()
    runScriptTests()
    runTableTests()
    runWebSocketTests()
end

runAllTests()