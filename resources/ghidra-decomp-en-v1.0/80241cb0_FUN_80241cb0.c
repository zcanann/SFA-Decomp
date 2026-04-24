// Function: FUN_80241cb0
// Entry: 80241cb0
// Size: 172 bytes

uint FUN_80241cb0(int param_1,int param_2,int param_3)

{
  uint uVar1;
  uint uVar2;
  
  uVar2 = param_3 + 0x1fU >> 5;
  uVar1 = uVar2 + 0x7f;
  while (uVar2 != 0) {
    if (uVar2 < 0x80) {
      FUN_80241c8c(param_1,param_2,uVar2);
      uVar2 = 0;
    }
    else {
      FUN_80241c8c(param_1,param_2,0);
      uVar2 = uVar2 - 0x80;
      param_1 = param_1 + 0x1000;
      param_2 = param_2 + 0x1000;
    }
  }
  return uVar1 >> 7;
}

