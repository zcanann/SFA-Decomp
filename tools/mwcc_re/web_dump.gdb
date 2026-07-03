set pagination off
set height 0
set width 0
break call_EntryProc
run
delete 1
break *0x508680
commands 2
silent
printf "==DRIVER cls=%d==\n", *(char*)0x5ea299
continue
end
break *0x50899e
commands 3
silent
printf "A cls=%d idx=%d nadj=%d reg=%d val=%08x\n", *(char*)0x5ea299, *(unsigned short*)($ebx+0x10), *(short*)($ebx+0x18), $ecx, *(unsigned int*)($ebx+0x04)
continue
end
break *0x5089c4
commands 4
silent
printf "F idx=%d nadj=%d reg=%d val=%08x\n", *(unsigned short*)($ebx+0x10), *(short*)($ebx+0x18), $eax, *(unsigned int*)($ebx+0x04)
continue
end
continue
quit
