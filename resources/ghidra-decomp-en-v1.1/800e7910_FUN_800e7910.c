// Function: FUN_800e7910
// Entry: 800e7910
// Size: 144 bytes

void FUN_800e7910(undefined4 param_1,uint *param_2)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = *param_2;
  if ((((uVar2 & 0x4000000) != 0) && ((uVar2 & 0x2000) != 0)) &&
     ((*(char *)((int)param_2 + 0x25b) == '\x01' || (*(char *)((int)param_2 + 0x25b) == '\x02')))) {
    uVar1 = (uint)((uVar2 & 4) != 0);
    if ((uVar2 & 0x1000000) != 0) {
      uVar1 = uVar1 | 0x20;
    }
    FUN_8006933c(param_1,param_2 + 0x90,uVar1,'\x01');
  }
  return;
}

