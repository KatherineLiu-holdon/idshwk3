global userAgents : table[addr] of set[string] = table();
event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
{
  if(is_orig)
  {
    if(c$conn_id$orig_h in userAgents)
    {
      add userAgents[c$conn_id$orig_h][c$http$user_agent]
    }
  }  
}

event zeek_done()
{
  for(address in userAgents)
  {
    if()
	  {
      print address," is a proxy";
    }
  }

}
