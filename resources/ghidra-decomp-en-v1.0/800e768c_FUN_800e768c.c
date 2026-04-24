// Function: FUN_800e768c
// Entry: 800e768c
// Size: 144 bytes

void FUN_800e768c(undefined4 param_1,uint *param_2)

{
  uint uVar1;
  byte bVar2;
  
  uVar1 = *param_2;
  if ((((uVar1 & 0x4000000) != 0) && ((uVar1 & 0x2000) != 0)) &&
     ((*(char *)((int)param_2 + 0x25b) == '\x01' || (*(char *)((int)param_2 + 0x25b) == '\x02')))) {
    bVar2 = (uVar1 & 4) != 0;
    if ((uVar1 & 0x1000000) != 0) {
      bVar2 = bVar2 | 0x20;
    }
    FUN_800691c0(param_1,param_2 + 0x90,bVar2,1);
  }
  return;
}

