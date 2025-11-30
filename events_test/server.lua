RegisterServerEvent('Secret_server_event')

AddEventHandler('Secret_server_event', function(data)
  print('Secret_server_event: ' .. data)
end)