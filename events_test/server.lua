RegisterServerEvent('Secret_server_event')

function echo(text)
        print("Echo from server! "..text)
end

RegisterCommand('tce', function(source, args)
        TriggerClientEvent("Secret_server_event", -1, {tab={1,2,3}, num=42, callback=echo})
end)

AddEventHandler('Secret_server_event', function(data)
  print(json.encode(data))
end)