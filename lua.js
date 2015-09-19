message = "Hello world!"



local Animal = {}
function Animal:new(o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
end

function Animal:speak()
    print("I dont't known how")
end

local Dog = Animal:new()
function Dog:speak()
    return "wuff wuff"
end

local Cat = Animal:new()
function Cat:speak()
    return "meow"
end

local function foo(s)
    local arr = {}
    local k = { foo="bar", bar={x=42} }
    arr["j"] = k
    --arr["2"] = 2
    arr[2] = -2
    k.bar.x = 23;
    local temp = arr.j.bar.x
    print(message)
    local cat = Cat:new({hunger=0})
    print(cat:speak())
    local dog = Dog:new()
    print(dog:speak())
    sleep(s["sleep"])
end

while true do
   foo({sleep=1})
end
