global userAgents : table[addr] of set[string] = table();
event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
{
  if(is_orig && name=="USER-AGENT")
  {
    if(c$id$orig_h in userAgents)
    {
      add userAgents[c$id$orig_h][value];
    }
    else
    {
    	userAgents[c$id$orig_h]=set();
    	add userAgents[c$id$orig_h][value];
    }
  }  
}

event zeek_done()
{
  for(address in userAgents)
  {
    if(|userAgents[address]|>=3)
	  {
      print fmt("%s is a proxy",address);
    }
  }

}

