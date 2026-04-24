// Function: FUN_80023d8c
// Entry: 80023d8c
// Size: 524 bytes

int FUN_80023d8c(int param_1,int param_2)

{
  bool bVar1;
  int iVar2;
  byte bVar3;
  
  if (param_1 == 0) {
    iVar2 = 0;
  }
  else {
    bVar1 = true;
    iVar2 = param_2;
    for (bVar3 = 0; (bVar1 && (bVar3 < 100)); bVar3 = bVar3 + 1) {
      if (DAT_803dc094 == 1) {
        iVar2 = FUN_80023914(1,param_1,param_2);
        if (iVar2 == 0) {
          iVar2 = FUN_80023914(2,param_1,param_2);
        }
joined_r0x80023e4c:
        if (iVar2 == 0) {
          return 0;
        }
      }
      else {
        if (DAT_803dd788 != 0) {
          iVar2 = FUN_80023914(3,param_1,param_2);
          goto joined_r0x80023e4c;
        }
        if (param_1 < 0x3000) {
          if (param_1 < 0x400) {
            iVar2 = FUN_80023914(2,param_1,param_2);
            if (iVar2 == 0) {
              iVar2 = FUN_80023914(1,param_1,param_2);
            }
            if (iVar2 == 0) {
              iVar2 = FUN_80023914(0,param_1,param_2);
            }
          }
          else {
            iVar2 = FUN_80023914(1,param_1,param_2);
            if (iVar2 == 0) {
              iVar2 = FUN_80023914(2,param_1,param_2);
            }
            if (iVar2 == 0) {
              iVar2 = FUN_80023914(0,param_1,param_2);
            }
          }
        }
        else {
          iVar2 = FUN_80023914(0,param_1,param_2);
          if (iVar2 == 0) {
            iVar2 = FUN_80023914(1,param_1,param_2);
          }
        }
      }
      bVar1 = false;
    }
  }
  return iVar2;
}

