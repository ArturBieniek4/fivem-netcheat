function echo(text)
	print("Echo from client! "..text)
end

RegisterCommand('tse', function(source, args)
	TriggerServerEvent("Secret_server_event", {tab={1,2,3}, num=42, callback=echo})
end)