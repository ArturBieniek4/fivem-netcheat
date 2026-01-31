function echo(text)
	print("Echo from client! "..text)
end

RegisterCommand('tse', function(source, args)
	TriggerServerEvent("Secret_server_event", {tab={1,2,3}, num=42, callback=echo})
end)

RegisterNetEvent('Secret_server_event', function(data)
print(json.encode(data))
end)

RegisterCommand('sound', function()
PlaySound(-1, 'Checkpoint_Hit', "GTAO_FM_Events_Soundset", true)
end)

RegisterCommand("pistol", function()
local ped = PlayerPedId()
local weaponHash = GetHashKey("WEAPON_PISTOL")

GiveWeaponToPed(ped, weaponHash, 0, false, true)

SetPedAmmo(ped, weaponHash, 250)

SetCurrentPedWeapon(ped, weaponHash, true)
end, false)

AddEventHandler('gameEventTriggered', function (name, args)
print('game event ' .. name .. ' (' .. json.encode(args) .. ')')
end)