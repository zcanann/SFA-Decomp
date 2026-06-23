set pagination off
set height 0
set width 0
break call_EntryProc
run
delete 1
break *0x508680
continue
echo \n==TABLES==\n
echo GPR4_count:\n
x/1dw 0x5e960c
echo GPR4_order_0x5e3d68:\n
x/24dw 0x5e3d68
echo class3_count:\n
x/1dw 0x5e9608
echo class3_order_0x5e3ce8:\n
x/24dw 0x5e3ce8
echo ==ENDTABLES==\n
delete 2
break *0x50899e
commands 3
silent
printf "A %x %d\n", $edx, $ecx
continue
end
break *0x5089c4
commands 4
silent
printf "F %d\n", $eax
continue
end
break *0x5089f7
commands 5
silent
printf "S\n"
continue
end
continue
quit
