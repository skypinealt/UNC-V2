local passCount, failCount, undefinedCount, runningTests, cClosureCount, luaClosureCount = 0, 0, 0, 0, 0, 0

function cloneref(object) return object end

local function getGlobal(path)
    local currentTable = getfenv(0)
    while currentTable ~= nil and path ~= "" do
        local key, remainingPath = string.match(path, "^([^.]+)%.?(.*)$")
        currentTable = currentTable[key]
        path = remainingPath
    end
    return currentTable
end

local function getClosureType(func)
    if iscclosure then
        return iscclosure(func) and "C closure" or "Lua closure"
    else
        if debug.info(func, 's') == "[C]" then
            return "C closure"
        else
            return "Lua closure"
        end
    end
end

local function test(testName, aliasList, testCallback, target, index)
    runningTests = runningTests + 1
    local targetFunction = target
    if index and target then
        targetFunction = target[index]
    end
    task.spawn(function()
        if testName == "script" then
            local scriptDefined, scriptValue = pcall(function() return script end)
            if scriptDefined and scriptValue ~= nil then
                local parentCheckPassed, errorMessage = pcall(function()
                    assert(scriptValue.Parent == nil, "Source script should be parented to nil")
                end)
                if parentCheckPassed then
                    passCount = passCount + 1
                    print("✅ " .. testName)
                else
                    failCount = failCount + 1
                    warn("⛔ " .. testName .. " failed: " .. errorMessage)
                end
            else
                failCount = failCount + 1
                warn("⛔ " .. testName .. " failed: script is not defined or nil")
            end
            runningTests = runningTests - 1
            return
        elseif not testCallback then
            print("⏺️ " .. testName)
        elseif not getGlobal(testName) then
            failCount = failCount + 1
            warn("⛔ " .. testName)
        else
            local success, message = pcall(testCallback)
            local closureType
            if targetFunction then
                closureType = getClosureType(targetFunction)
                if closureType == "C closure" then
                    cClosureCount = cClosureCount + 1
                else
                    luaClosureCount = luaClosureCount + 1
                end
            end
            if closureType then
                if success then
                    passCount = passCount + 1
                    print("✅ " .. testName .. (message and " • " .. message or "") .. " - " .. closureType)
                else
                    failCount = failCount + 1
                    warn("⛔ " .. testName .. " failed: " .. message .. " - " .. closureType)
                end
            else
                if success then
                    passCount = passCount + 1
                    print("✅ " .. testName .. (message and " • " .. message or ""))
                else
                    failCount = failCount + 1
                    warn("⛔ " .. testName .. " failed: " .. message)
                end
            end
        end

        local undefinedAliases = {}
        for _, alias in ipairs(aliasList) do
            if getGlobal(alias) == nil then
                table.insert(undefinedAliases, alias)
            end
        end
        if #undefinedAliases > 0 then
            undefinedCount = undefinedCount + 1
            warn("⚠️ " .. table.concat(undefinedAliases, ", "))
        end
        runningTests = runningTests - 1
    end)
end

local function shallowEqual(table1, table2)
    if table1 == table2 then return true end
    local uniqueTypes = { ["function"] = true, ["table"] = true, ["userdata"] = true, ["thread"] = true }
    for key, value in pairs(table1) do
        if uniqueTypes[type(value)] then
            if type(table2[key]) ~= type(value) then return false end
        elseif table2[key] ~= value then
            return false
        end
    end
    for key, value in pairs(table2) do
        if uniqueTypes[type(value)] then
            if type(table1[key]) ~= type(value) then return false end
        elseif table1[key] ~= value then
            return false
        end
    end
    return true
end

print("UNC Env Check")
print("✅ - Pass, ⛔ - Fail, ⏺️ - No test, ⚠️ - Missing aliases\n")

task.defer(function()
    repeat task.wait() until runningTests == 0
    local totalTests = passCount + failCount
    local successRate = totalTests > 0 and math.round(passCount / totalTests * 100) or 0
    local testSummary = passCount .. " out of " .. totalTests
    local totalFunctionsTested = cClosureCount + luaClosureCount
    local cClosurePercentage = totalFunctionsTested > 0 and math.round(cClosureCount / totalFunctionsTested * 100) or 0
    local luaClosurePercentage = totalFunctionsTested > 0 and math.round(luaClosureCount / totalFunctionsTested * 100) or 0
    print("UNC Test Result")
    print("✅ Completed all tests with a " .. successRate .. "% success rate (" .. testSummary .. ")")
    print("⛔ " .. failCount .. " function tests failed")
    print("⚠️ " .. undefinedCount .. " function globals are missing aliases")
    print("ℹ️ " .. cClosurePercentage .. "% of functions are C closures (" .. cClosureCount .. ")")
    print("ℹ️ " .. luaClosurePercentage .. "% of functions are Lua closures (" .. luaClosureCount .. ")")
    print("Build: 030925162 | Credit: sharpcystals")
end)

--- Cache Functions
test("cache.invalidate", {}, function()
    local testContainer = Instance.new("Folder")
    local testPart = Instance.new("Part", testContainer)
    cache.invalidate(testContainer:FindFirstChild("Part"))
    assert(testPart ~= testContainer:FindFirstChild("Part"), "Reference `testPart` could not be invalidated")
end, cache, 'invalidate')

test("cache.iscached", { "cache.cached" }, function()
    local testPart = Instance.new("Part")
    assert(cache.iscached(testPart), "Part should be cached")
    cache.invalidate(testPart)
    assert(not cache.iscached(testPart), "Part should not be cached")
end, cache, 'iscached')

test("cache.replace", {}, function()
    local originalPart = Instance.new("Part")
    local replacementFire = Instance.new("Fire")
    cache.replace(originalPart, replacementFire)
    assert(originalPart ~= replacementFire, "Part was not replaced with Fire")
end, cache, 'replace')

test("cloneref", { "clonereference" }, function()
    local originalPart = Instance.new("Part")
    local clonedPart = cloneref(originalPart)
    assert(originalPart ~= clonedPart, "Clone should not equal original")
    clonedPart.Name = "Test"
    assert(originalPart.Name == "Test", "Clone should update original")
    assert(typeof(clonedPart) == typeof(originalPart), "Clone type should match original")
end, cloneref)

test("compareinstances", {}, function()
    local originalPart = Instance.new("Part")
    local clonedPart = cloneref(originalPart)
    assert(originalPart ~= clonedPart, "Clone should not equal original")
    assert(compareinstances(originalPart, clonedPart), "Clones should be equal via compareinstances")
end, compareinstances)

--- Closure Functions
test("checkcaller", {}, function()
    assert(checkcaller(), "Main scope should return true")
end, checkcaller)

test("clonefunction", {}, function()
    local function sampleFunction() return "success" end
    local clonedFunction = clonefunction(sampleFunction)
    assert(sampleFunction() == clonedFunction(), "Clone should match original return value")
    assert(sampleFunction ~= clonedFunction, "Clone should not equal original")
end, clonefunction)

test("getcallingscript", { "getcaller" }, function()
    assert(getcallingscript() == script, "Caller should match current script")
end, getcallingscript)

test("getscriptclosure", { "getscriptfunction" }, function()
    local module = game:GetService("CoreGui").RobloxGui.Modules.Common.Constants
    local constants = getrenv().require(module)
    local generatedConstants = getscriptclosure(module)()
    assert(constants ~= generatedConstants, "Generated module should differ from original")
    assert(shallowEqual(constants, generatedConstants), "Generated constants should shallow equal original")
end, getscriptclosure)

test("hookfunction", { "replaceclosure" }, function()
    local function sampleFunction() return true end
    local originalFunction = hookfunction(sampleFunction, function() return false end)
    assert(sampleFunction() == false, "Hooked function should return false")
    assert(originalFunction() == true, "Original should return true")
    assert(sampleFunction ~= originalFunction, "Hooked should differ from original")
end, hookfunction)

test("hooksignal", {"replacecon"}, function()
    local testPart = Instance.new("Part")
    local changedProperty = nil
    testPart.Changed:Connect(function(prop) changedProperty = prop end)
    hooksignal(testPart.Changed, function(info, prop) return true, "Hooked" end)
    testPart.Name = "NewName"
    assert(changedProperty == "Hooked", "Signal should be hooked")
end, hooksignal)

test("iscclosure", {}, function()
    assert(iscclosure(print) == true, "print should be a C closure")
    assert(iscclosure(function() end) == false, "Anonymous function should not be a C closure")
end, iscclosure)

test("isfunctionhooked", {}, function()
    local function sampleFunction() return true end
    hookfunction(sampleFunction, function() return false end)
    assert(isfunctionhooked(sampleFunction), "Function should be marked as hooked")
end, isfunctionhooked)

test("issignalhooked", {}, function()
    local testPart = Instance.new("Part")
    local changedProperty = nil
    testPart.Changed:Connect(function(prop) changedProperty = prop end)
    hooksignal(testPart.Changed, function(info, prop) return true, "Hooked" end)
    testPart.Name = "NewName"
    assert(changedProperty == "Hooked", "Signal should be hooked")
    assert(issignalhooked(testPart.Changed), "Signal should be marked as hooked")
end, issignalhooked)

test("islclosure", {}, function()
    assert(islclosure(print) == false, "print should not be a Lua closure")
    assert(islclosure(function() end) == true, "Anonymous function should be a Lua closure")
end, islclosure)

test("isexecutorclosure", { "checkclosure", "isourclosure", "isexploitclosure" }, function()
    assert(isexecutorclosure(isexecutorclosure) == true, "Executor global should return true")
    assert(isexecutorclosure(newcclosure(function() end)) == true, "Executor C closure should return true")
    assert(isexecutorclosure(function() end) == true, "Executor Lua closure should return true")
    assert(isexecutorclosure(print) == false, "Roblox global should return false")
end, isexecutorclosure)

test("loadstring", {}, function()
    if getscriptbytecode then
        local animateScript = game:GetService("Players").LocalPlayer.Character.Animate
        local bytecode = getscriptbytecode(animateScript)
        local loadedFunc = loadstring(bytecode)
        assert(type(loadedFunc) ~= "function", "Luau bytecode should not be loadable")
        assert(assert(loadstring("return ... + 1"))(1) == 2, "loadstring failed to load Lua code")
        assert(type(select(2, loadstring("f"))) == "string", "loadstring should return error for invalid code")
    else
        local loadedFunc = loadstring("getgenv().UNCtest = 1")
        assert(type(loadedFunc) == "function", "loadstring did not return a function")
        local success, err = pcall(loadedFunc)
        assert(success, "loadstring failed to execute: " .. (err or "unknown error"))
        assert(getgenv().UNCtest, "loadstring did not set global")
        getgenv().UNCtest = nil
    end
end, loadstring)

test("newcclosure", {}, function()
    local function sampleFunction() return true end
    local cClosureFunction = newcclosure(sampleFunction)
    assert(sampleFunction() == cClosureFunction(), "C closure should match original return")
    assert(sampleFunction ~= cClosureFunction, "C closure should differ from original")
    assert(iscclosure(cClosureFunction), "Should be a C closure")
end, newcclosure)

test("restorefunction", {}, function()
    local originalVersion = version
    version = function(...) end
    task.defer(function() getfenv().version = originalVersion end)
    assert(version ~= originalVersion, "Function tampering failed")
    restorefunction(version)
    assert(version == originalVersion, "Function not restored")
end, restorefunction)

test("restoresignal", {}, function()
    local testPart = Instance.new("Part")
    local changedProperty = nil
    testPart.Changed:Connect(function(prop) changedProperty = prop end)
    hooksignal(testPart.Changed, function(info, prop) return true, "Hooked" end)
    testPart.Name = "NewName"
    assert(changedProperty == "Hooked", "Signal should be hooked")
    assert(issignalhooked(testPart.Changed), "Signal should be marked as hooked")
    restoresignal(testPart.Changed)
    testPart.Name = "NewName2"
    assert(changedProperty ~= "Hooked", "Signal should not be hooked")
    assert(not issignalhooked(testPart.Changed), "Signal should not be marked as hooked")
end, restoresignal)

--- Crypt Functions
test("crypt.base64decode", { "crypt.base64.decode", "crypt.base64_decode", "base64.decode", "base64_decode" }, function()
    assert(crypt.base64decode("dGVzdA==") == "test", "Base64 decoding failed for 'test'")
    assert(crypt.base64decode("aGVsbG8=") == "hello", "Base64 decoding failed for 'hello'")
end, crypt, 'base64decode')

test("crypt.base64encode", { "crypt.base64.encode", "crypt.base64_encode", "base64.encode", "base64_encode" }, function()
    assert(crypt.base64encode("test") == "dGVzdA==", "Base64 encoding failed for 'test'")
    assert(crypt.base64encode("hello") == "aGVsbG8=", "Base64 encoding failed for 'hello'")
end, crypt, 'base64encode')

test("crypt.decrypt", {}, function()
    local key, iv = crypt.generatekey(), crypt.generatekey()
    local encryptedData = crypt.encrypt("test", key, iv, "CBC")
    local decryptedData = crypt.decrypt(encryptedData, key, iv, "CBC")
    assert(decryptedData == "test", "Decryption failed")
end, crypt, 'decrypt')

test("crypt.encrypt", {}, function()
    local key = crypt.generatekey()
    local encryptedData, iv = crypt.encrypt("test", key, nil, "CBC")
    assert(iv, "encrypt should return an IV")
    local decryptedData = crypt.decrypt(encryptedData, key, iv, "CBC")
    assert(decryptedData == "test", "Encryption/decryption cycle failed")
end, crypt, 'encrypt')

test("crypt.generatebytes", {}, function()
    local byteSize = math.random(10, 100)
    local generatedBytes = crypt.generatebytes(byteSize)
    assert(#crypt.base64decode(generatedBytes) == byteSize, "Generated bytes length mismatch")
end, crypt, 'generatebytes')

test("crypt.generatekey", {}, function()
    local generatedKey = crypt.generatekey()
    assert(#crypt.base64decode(generatedKey) == 32, "Key should be 32 bytes when decoded")
end, crypt, 'generatekey')

test("crypt.hash", {}, function()
    local hashAlgorithms = { 'sha1', 'sha384', 'sha512', 'md5', 'sha256', 'sha3-224', 'sha3-256', 'sha3-512' }
    for _, algorithm in ipairs(hashAlgorithms) do
        local hashValue = crypt.hash("test", algorithm)
        assert(hashValue, "Hash failed for algorithm: " .. algorithm)
    end
end, crypt, 'hash')

--- Debug Functions
test("debug.getconstant", { "getconstant", "getconst", "debug.getconst" }, function()
    local function sampleFunction() print("Hello, world!") end
    assert(debug.getconstant(sampleFunction, 1) == "print", "First constant should be 'print'")
    assert(debug.getconstant(sampleFunction, 2) == nil, "Second constant should be nil")
    assert(debug.getconstant(sampleFunction, 3) == "Hello, world!", "Third constant should be 'Hello, world!'")
    if debug.getconstants then
        assert(not pcall(function() local size = #debug.getconstants(sampleFunction); debug.getconstant(sampleFunction, size + 1) end),
            "Should check constant bounds")
    end
end, debug, 'getconstant')

test("debug.getconstants", { "getconstants", "getconsts", "debug.getconsts" }, function()
    local function sampleFunction()
        local num = 5000 .. 50000
        print("Hello, world!", num, warn)
    end
    local constants = debug.getconstants(sampleFunction)
    assert(constants[1] == 50000, "First constant should be 50000")
    assert(constants[2] == "print", "Second constant should be 'print'")
    assert(constants[4] == "Hello, world!", "Fourth constant should be 'Hello, world!'")
    assert(constants[5] == "warn", "Fifth constant should be 'warn'")
end, debug, 'getconstants')

test("debug.getinfo", { "debug.getfunctioninfo", "debug.getfuncinfo" }, function()
    local expectedTypes = {
        source = "string", short_src = "string", func = "function", what = "string",
        currentline = "number", name = "string", nups = "number", numparams = "number", is_vararg = "number"
    }
    local function sampleFunction(...) print(...) end
    local info = debug.getinfo(sampleFunction)
    for key, expectedType in pairs(expectedTypes) do
        assert(info[key] ~= nil, "Missing field: " .. key)
        assert(type(info[key]) == expectedType, "Field " .. key .. " should be " .. expectedType)
    end
end, debug, 'getinfo')

test("debug.getmetatable", {"getrawmetatable"}, function()
    local metatable = { __metatable = "Locked!" }
    local object = setmetatable({}, metatable)
    assert(debug.getmetatable(object) == metatable, "Did not return the metatable")
end, debug, 'getmetatable')

test("debug.getproto", { "getproto" }, function()
    local function outerFunction()
        local function innerFunction() return true end
    end
    local protoFunction = debug.getproto(outerFunction, 1, true)[1]
    local realProto = debug.getproto(outerFunction, 1)
    assert(protoFunction, "Failed to retrieve inner function")
    assert(protoFunction() == true, "Inner function should return true")
    if not realProto() then return "Proto return values disabled" end
end, debug, 'getproto')

test("debug.getprotos", { "getprotos" }, function()
    local function outerFunction()
        local function proto1() return true end
        local function proto2() return true end
    end
    for i, proto in ipairs(debug.getprotos(outerFunction)) do
        local protoFunction = debug.getproto(outerFunction, i, true)[1]
        assert(protoFunction(), "Failed to get inner function " .. i)
    end
end, debug, 'getprotos')

test("debug.getregistry", { "getregistry", "getreg", "debug.getreg" }, function()
    assert(typeof(debug.getregistry()) == "table", "Should return a table")
    assert(#debug.getregistry() ~= 0, "Registry should not be empty")
end, debug, 'getregistry')

test("debug.setmetatable", {"setrawmetatable"}, function()
    local object = setmetatable({}, { __index = function() return false end, __metatable = "Locked!" })
    local objectReturned = debug.setmetatable(object, { __index = function() return true end })
    assert(object.test == true, "Failed to change metatable")
    if objectReturned then return objectReturned == object and "Returned original" or "Did not return original" end
end, debug, 'setmetatable')

test("debug.getstack", {}, function()
    local _ = "a" .. "b"
    assert(debug.getstack(1, 1) == "ab", "First stack item should be 'ab'")
    assert(debug.getstack(1)[1] == "ab", "Stack table first item should be 'ab'")
end, debug, 'getstack')

test("debug.getupvalue", { "getupvalue", "getupval" }, function()
    local upvalueFunc = function() end
    local function sampleFunction() print(upvalueFunc) end
    assert(debug.getupvalue(sampleFunction, 1) == upvalueFunc, "Unexpected upvalue")
end, debug, 'getupvalue')

test("debug.getupvalues", { "getupvalues", "getupvals", "debug.getupvals" }, function()
    local upvalueFunc = function() end
    local function sampleFunction() print(upvalueFunc) end
    local upvalues = debug.getupvalues(sampleFunction)
    assert(upvalues[1] == upvalueFunc, "Unexpected upvalues")
end, debug, 'getupvalues')

test("debug.setconstant", { "setconst", "setconstants", "debug.setconsts" }, function()
    local function sampleFunction() return "fail" end
    debug.setconstant(sampleFunction, 1, "success")
    assert(sampleFunction() == "success", "Failed to set constant")
end, debug, 'setconstant')

test("debug.setstack", {}, function()
    local function sampleFunction()
        return "fail", debug.setstack(1, 1, "success")
    end
    assert(sampleFunction() == "success", "Failed to set stack")
end, debug, 'setstack')

test("debug.setupvalue", { "setupvalue", "setupvals", "debug.setupvals" }, function()
    local function upvalueFunc() return "fail" end
    local function sampleFunction() return upvalueFunc() end
    debug.setupvalue(sampleFunction, 1, function() return "success" end)
    assert(sampleFunction() == "success", "Failed to set upvalue")
end, debug, 'setupvalue')

--- Drawing Functions
test("cleardrawcache", {}, function()
    local testDrawing = Drawing.new("Circle")
    testDrawing.Visible = false
    cleardrawcache()
    assert(testDrawing == nil, "Failed to clear drawing cache")
end, cleardrawcache)

test("Drawing.clear", {}, function()
    local testDrawing = Drawing.new("Image")
    testDrawing.Visible = false
    Drawing.clear()
end, Drawing, 'clear')

test("Drawing.Fonts", {}, function()
    assert(Drawing.Fonts.UI == 0, "UI font ID incorrect")
    assert(Drawing.Fonts.System == 1, "System font ID incorrect")
    assert(Drawing.Fonts.Plex == 2, "Plex font ID incorrect")
    assert(Drawing.Fonts.Monospace == 3, "Monospace font ID incorrect")
end)

test("Drawing.new", {}, function()
    local testDrawing = Drawing.new("Square")
    testDrawing.Visible = false
    local canDestroy = pcall(function() testDrawing:Destroy() end)
    assert(canDestroy, "Destroy should not error")
end, Drawing, 'new')

test("getrenderproperty", {}, function()
    local testDrawing = Drawing.new("Image")
    testDrawing.Visible = true
    assert(type(getrenderproperty(testDrawing, "Visible")) == "boolean", "Visible should be boolean")
    local success, result = pcall(function() return getrenderproperty(testDrawing, "Color") end)
    if not success or not result then return "Image.Color not supported" end
end, getrenderproperty)

test("isrenderobj", {}, function()
    local testDrawing = Drawing.new("Image")
    testDrawing.Visible = true
    assert(isrenderobj(testDrawing) == true, "Should return true for drawing")
    assert(isrenderobj(newproxy()) == false, "Should return false for non-drawing")
end, isrenderobj)

test("setrenderproperty", {}, function()
    local testDrawing = Drawing.new("Square")
    testDrawing.Visible = true
    setrenderproperty(testDrawing, "Visible", false)
    assert(testDrawing.Visible == false, "Failed to set Visible property")
end, setrenderproperty)

--- Filesystem Functions
if isfolder and makefolder and delfolder then
    if isfolder(".tests") then delfolder(".tests") end
    makefolder(".tests")
end

test("appendfile", {}, function()
    writefile(".tests/appendfile.txt", "su")
    appendfile(".tests/appendfile.txt", "cce")
    appendfile(".tests/appendfile.txt", "ss")
    assert(readfile(".tests/appendfile.txt") == "success", "Failed to append file")
end, appendfile)

test("delfile", {}, function()
    writefile(".tests/delfile.txt", "Hello, world!")
    delfile(".tests/delfile.txt")
    assert(not isfile(".tests/delfile.txt"), "Failed to delete file")
end, delfile)

test("delfolder", {}, function()
    makefolder(".tests/delfolder")
    delfolder(".tests/delfolder")
    assert(not isfolder(".tests/delfolder"), "Failed to delete folder")
end, delfolder)

test("isfile", {}, function()
    writefile(".tests/isfile.txt", "success")
    assert(isfile(".tests/isfile.txt") == true, "Should return true for file")
    assert(isfile(".tests") == false, "Should return false for folder")
end, isfile)

test("isfolder", {}, function()
    assert(isfolder(".tests") == true, "Should return true for folder")
    assert(isfolder(".tests/doesnotexist.exe") == false, "Should return false for nonexistent path")
end, isfolder)

test("listfiles", {}, function()
    makefolder(".tests/listfiles")
    writefile(".tests/listfiles/test_1.txt", "success")
    writefile(".tests/listfiles/test_2.txt", "success")
    local files = listfiles(".tests/listfiles")
    assert(#files == 2, "Incorrect number of files")
    assert(readfile(files[1]) == "success", "File content mismatch")
end, listfiles)

test("loadfile", {}, function()
    writefile(".tests/loadfile.txt", "return ... + 1")
    assert(assert(loadfile(".tests/loadfile.txt"))(1) == 2, "Failed to load file")
end, loadfile)

test("makefolder", {}, function()
    makefolder(".tests/makefolder")
    assert(isfolder(".tests/makefolder"), "Failed to create folder")
end, makefolder)

test("readfile", {}, function()
    writefile(".tests/readfile.txt", "success")
    assert(readfile(".tests/readfile.txt") == "success", "Failed to read file")
end, readfile)

test("writefile", {}, function()
    writefile(".tests/writefile.txt", "success")
    assert(readfile(".tests/writefile.txt") == "success", "Failed to write file")
end, writefile)

--- Instances Functions
test("filtergc", {}, function()
    local testTable = { UNC = "Testing" }
    local metatable = { __idiv = function() return 0.1515 end, __div = function() return "Ballers" end, __metatable = "Locked" }
    setmetatable({}, metatable)
    local filteredGC = filtergc("table", {
        KeyValuePairs = testTable,
        Keys = {"UNC"},
        Values = {"Testing"},
        Metatable = metatable
    })
    assert(#filteredGC > 0, "Should return filtered tables")
    assert(filteredGC[1] == testTable, "Incorrect table filtered")
end, filtergc)

test("fireclickdetector", {}, function()
    local clicked = false
    local detector = Instance.new("ClickDetector")
    detector.MouseClick:Connect(function() clicked = true end)
    fireclickdetector(detector, 1, "MouseClick")
    assert(clicked, "Failed to fire click detector")
end, fireclickdetector)

test("fireproximityprompt", {}, function()
    local prompt = Instance.new("ProximityPrompt")
    fireproximityprompt(prompt)
end, fireproximityprompt)

test("firesignal", {}, function()
    local event = Instance.new("BindableEvent")
    local result = false
    event.Event:Connect(function(arg) result = arg end)
    firesignal(event.Event, true)
    assert(result, "Failed to fire signal")
end, firesignal)

test("firetouchinterest", {}, function()
    local touchedCount = 0
    local testPart = Instance.new("Part", game:GetService("Workspace"))
    testPart.Touched:Connect(function() touchedCount = touchedCount + 1 end)
    firetouchinterest(testPart, game:GetService("Players").LocalPlayer.Character.PrimaryPart, 0)
    task.wait()
    firetouchinterest(testPart, game:GetService("Players").LocalPlayer.Character.PrimaryPart, 1)
    assert(touchedCount == 1, "Should activate touch only once")
    testPart:Destroy()
end, firetouchinterest)

test("getcacheinstances", {}, function()
    assert(getcacheinstances()[1]:IsA("Instance"), "Should return Instances")
end, getcacheinstances)

test("getcallbackvalue", {}, function()
    local bindable = Instance.new("BindableFunction")
    local function callbackFunc() end
    bindable.OnInvoke = callbackFunc
    assert(getcallbackvalue(bindable, "OnInvoke") == callbackFunc, "Failed to get callback")
end, getcallbackvalue)

test("getconnections", {}, function()
    local bindable = Instance.new("BindableEvent")
    bindable.Event:Connect(function() end)
    local connection = getconnections(bindable.Event)[1]
    assert(type(connection.Fire) == "function", "Connection should have Fire function")
end, getconnections)

test("getcustomasset", {}, function()
    writefile(".tests/getcustomasset.txt", "success")
    local contentId = getcustomasset(".tests/getcustomasset.txt")
    assert(string.match(contentId, "rbxasset://") == "rbxasset://", "Should return rbxasset URL")
end, getcustomasset)

test("gethiddenproperty", {}, function()
    local fire = Instance.new("Fire")
    local value, isHidden = gethiddenproperty(fire, "size_xml")
    assert(value == 5, "Incorrect hidden property value")
    assert(isHidden == true, "Should be hidden")
end, gethiddenproperty)

test("gethui", {}, function()
    local hui = gethui()
    assert(hui == game:GetService("CoreGui") or hui == game:GetService("Players").LocalPlayer.PlayerGui, "Incorrect HUI")
end, gethui)

test("getinstances", {}, function()
    assert(getinstances()[1]:IsA("Instance"), "Should return Instances")
end, getinstances)

test("getnamecallmethod", { "getncm", "get_namecall_method" }, function()
    pcall(function() game:NAMECALL_TEST() end)
    assert(getnamecallmethod() == "NAMECALL_TEST", "Failed to get namecall method")
end, getnamecallmethod)

test("getnilinstances", {}, function()
    local nilInstance = getnilinstances()[1]
    assert(nilInstance.Parent == nil, "Should have nil parent")
end, getnilinstances)

test("getproperties", {"getprops"}, function()
    local testPart = Instance.new("Part")
    local props = getproperties(testPart)
    assert(props.Position ~= testPart.Position, "Should return different Position")
end, getproperties)

test("isscriptable", {}, function()
    local fire = Instance.new("Fire")
    assert(not isscriptable(fire, "size_xml"), "size_xml should not be scriptable")
    assert(isscriptable(fire, "Size"), "Size should be scriptable")
end, isscriptable)

test("sethiddenproperty", {}, function()
    local fire = Instance.new("Fire")
    local success = sethiddenproperty(fire, "size_xml", 10)
    assert(success, "Failed to set hidden property")
    assert(gethiddenproperty(fire, "size_xml") == 10, "Value not set")
end, sethiddenproperty)

test("setnamecallmethod", { "setncm", "set_namecall_method" }, function()
    setnamecallmethod("GetService")
    local success = pcall(getrawmetatable(game).__namecall, game, "Workspace")
    assert(success, "Failed to set namecall method")
end, setnamecallmethod)

test("setscriptable", {}, function()
    local fire = Instance.new("Fire")
    local wasScriptable = setscriptable(fire, "size_xml", true)
    assert(not wasScriptable, "Should not have been scriptable")
    assert(isscriptable(fire, "size_xml"), "Should now be scriptable")
end, setscriptable)

--- Metatable Functions
test("getrawmetatable", {}, function()
    local metatable = { __metatable = "Locked!" }
    local object = setmetatable({}, metatable)
    assert(getrawmetatable(object) == metatable, "Failed to get raw metatable")
end, getrawmetatable)

test("hookmetamethod", {}, function()
    local object = setmetatable({}, { __index = newcclosure(function() return false end), __metatable = "Locked!" })
    local originalMethod = hookmetamethod(object, "__index", function() return true end)
    assert(object.test == true, "Failed to hook metamethod")
    assert(originalMethod() == false, "Original method not returned")
end, hookmetamethod)

test("isreadonly", {}, function()
    local frozenTable = table.freeze({})
    assert(isreadonly(frozenTable), "Should be read-only")
end, isreadonly)

test("setrawmetatable", {}, function()
    local object = setmetatable({}, { __index = function() return false end, __metatable = "Locked!" })
    local objectReturned = setrawmetatable(object, { __index = function() return true end })
    assert(object.test == true, "Failed to set raw metatable")
end, setrawmetatable)

test("setreadonly", {}, function()
    local testTable = { success = false }
    table.freeze(testTable)
    setreadonly(testTable, false)
    testTable.success = true
    assert(testTable.success, "Failed to make writable")
end, setreadonly)

--- Miscellaneous Functions
test("getclipboard", { "getrbxclipboard" }, function()
    assert(getclipboard() == "UNC", "Incorrect clipboard value")
end, getclipboard)

test("getfpscap", {}, function()
    assert(getfpscap() == 20, "Incorrect FPS cap")
    setfpscap(60)
end, getfpscap)

test("gethwid", { "get_hwid" }, function()
    assert(type(gethwid()) == "string", "HWID should be a string")
end, gethwid)

test("identifyexecutor", { "getexecutorname" }, function()
    local name, version = identifyexecutor()
    assert(type(name) == "string", "Name should be a string")
    return type(version) == "string" and "Version is string" or "No version"
end, identifyexecutor)

test("isnetworkowner", {"isowner"}, function()
    assert(isnetworkowner(game:GetService("Players").LocalPlayer.Character.HumanoidRootPart), "Should be network owner")
end, isnetworkowner)

test("isrbxactive", { "isgameactive" }, function()
    assert(type(isrbxactive()) == "boolean", "Should return boolean")
end, isrbxactive)

test("lz4compress", {}, function()
    local rawData = "Hello, world!"
    local compressedData = lz4compress(rawData)
    assert(lz4decompress(compressedData, #rawData) == rawData, "Compression failed")
end, lz4compress)

test("lz4decompress", {}, function()
    local rawData = "Hello, world!"
    local compressedData = lz4compress(rawData)
    assert(lz4decompress(compressedData, #rawData) == rawData, "Decompression failed")
end, lz4decompress)

test("printidentity", {}, function()
    local identity
    local conn = game:GetService("LogService").MessageOut:Connect(function(message)
        if message:find("Current identity is") then identity = tonumber(message:match("%d+")) end
    end)
    printidentity()
    repeat task.wait() until identity
    conn:Disconnect()
    assert(identity <= 9, "Identity should not exceed 9")
end, printidentity)

test("setclipboard", { "setrbxclipboard", "toclipboard" }, function()
    setclipboard("UNC")
end, setclipboard)

test("secure_call", {}, function()
    assert(not pcall(secure_call, "hello = nil"), "Should only accept functions")
end, secure_call)

test("setfpscap", {}, function()
    setfpscap(60)
end, setfpscap)

test("request", { "http.request", "http_request" }, function()
    local response = request({ Url = "https://httpbin.org/user-agent", Method = "GET" })
    assert(response.StatusCode == 200, "Request failed")
    local data = game:GetService("HttpService"):JSONDecode(response.Body)
    assert(type(data["user-agent"]) == "string", "User-agent missing")
    return "User-Agent: " .. data["user-agent"]
end, request)

--- Scripts Functions
test("getallthreads", { "getthreads" }, function()
    assert(type(getallthreads()[1]) == "thread", "Should return threads")
end, getallthreads)

test("getgc", { "getgarbagecollector" }, function()
    assert(#getgc() ~= 0, "Should return garbage collected items")
end, getgc)

test("getgenv", {}, function()
    getgenv().__TEST = true
    assert(__TEST, "Failed to set global")
    getgenv().__TEST = nil
end, getgenv)

test("getloadedmodules", {}, function()
    assert(getloadedmodules()[1]:IsA("ModuleScript"), "Should return ModuleScripts")
end, getloadedmodules)

test("getrenv", {}, function()
    assert(_G ~= getrenv()._G, "Executor _G should differ from game _G")
end, getrenv)

test("getrunningscripts", {}, function()
    local scripts = getrunningscripts()
    assert(scripts[1]:IsA("ModuleScript") or scripts[1]:IsA("LocalScript"), "Should return scripts")
end, getrunningscripts)

test("getscriptbytecode", { "dumpstring" }, function()
    local animate = game:GetService("Players").LocalPlayer.Character.Animate
    assert(type(getscriptbytecode(animate)) == "string", "Should return bytecode string")
end, getscriptbytecode)

test("getscripthash", {}, function()
    local animate = game:GetService("Players").LocalPlayer.Character.Animate:Clone()
    local originalHash = getscripthash(animate)
    animate.Source = "print('Hello')"
    assert(getscripthash(animate) ~= originalHash, "Hash should change with source")
end, getscripthash)

test("getscripts", {}, function()
    assert(getscripts()[1]:IsA("LocalScript") or getscripts()[1]:IsA("ModuleScript"), "Should return scripts")
end, getscripts)

test("getsenv", {}, function()
    local animate = game:GetService("Players").LocalPlayer.Character.Animate
    local env = getsenv(animate)
    assert(env.script == animate, "Script env should match")
end, getsenv)

test("gettenv", {}, function()
    local thread = task.defer(function() end)
    local env = gettenv(thread)
    assert(type(env) == "table", "Should return environment table")
end, gettenv)

test("getscriptthread", {}, function()
    assert(type(getscriptthread(game:GetService("Players").LocalPlayer.Character.Animate)) == "thread", "Should return thread")
end, getscriptthread)

test("getthreadidentity", { "getidentity", "getthreadcontext" }, function()
    assert(type(getthreadidentity()) == "number", "Should return number")
end, getthreadidentity)

test("setthreadidentity", { "setidentity", "setthreadcontext" }, function()
    setthreadidentity(3)
    assert(getthreadidentity() == 3, "Failed to set identity")
end, setthreadidentity)

--- Table Functions
test("table.freeze", {"freeze"}, function()
    local originalTable = {{}}
    local frozenTable = table.freeze(originalTable)
    assert(not pcall(function() originalTable[1] = {} end), "Table should be frozen")
end, table, 'freeze')

test("table.isfrozen", {"isfrozen"}, function()
    local frozenTable = table.freeze({})
    assert(table.isfrozen(frozenTable), "Should be frozen")
end, table, 'isfrozen')

test("table.unfreeze", {"unfreeze"}, function()
    local frozenTable = table.freeze({})
    local unfrozenTable = table.unfreeze(frozenTable)
    unfrozenTable.test = true
    assert(unfrozenTable.test, "Should be modifiable")
end, table, 'unfreeze')

--- WebSocket Functions
test("WebSocket.connect", {}, function()
    local ws = WebSocket.connect("ws://echo.websocket.events")
    assert(type(ws.Send) == "function", "Should have Send function")
end, WebSocket, 'connect')
