global oriRes : table[addr] of int = table();
global ori404 : table[addr] of int = table();
global oriUrl : table[addr] of set[string];
global t:time;
global t2:interval=10min;

event zeek_init()
{
 t=current_time();
}
event http_reply(c: connection, version: string, code: count, reason: string)
{ 
if(c$start_time - t2 <= t)
{
if (c$id$orig_h !in oriRes)
{oriRes[c$id$orig_h]=0;}
if (c$id$orig_h !in ori404)
{ori404[c$id$orig_h]=0;}

   oriRes[c$id$orig_h] += 1;
   if (code == 404 ){ 
       ori404[c$id$orig_h] += 1;
       local theurl : string = [HTTP::build_url(c$http)];
       oriUrl[c$id$orig_h];
       local ss : set[string] = oriUrl[c$id$orig_h];
       add ss[theurl];
       oriUrl[c$id$orig_h] = ss;
   } 
}
}
event zeek_done()
{ 
for(a, num4 in ori404)
{ 
   if( num4 > 2){
     if( oriRes[a] / num4 < 5){ 
		local ss2 : set[string] = oriUrl[a];
		local numurl : int =|ss2|;
		if( num4  / numurl < 2){
		   print fmt("%s is a scanner with %d scan attemps on %d urls", a,num4,numurl );
		}
     }
   }
}
}
