// Function: FUN_80023cc8
// Entry: 80023cc8
// Size: 524 bytes

int FUN_80023cc8(int param_1,int param_2,undefined4 param_3)

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
      if (DAT_803db434 == 1) {
        iVar2 = FUN_80023850(1,param_1,param_2,param_3);
        if (iVar2 == 0) {
          iVar2 = FUN_80023850(2,param_1,param_2,param_3);
        }
joined_r0x80023d88:
        if (iVar2 == 0) {
          return 0;
        }
      }
      else {
        if (DAT_803dcb08 != 0) {
          iVar2 = FUN_80023850(3,param_1,param_2,param_3);
          goto joined_r0x80023d88;
        }
        if (param_1 < 0x3000) {
          if (param_1 < 0x400) {
            iVar2 = FUN_80023850(2,param_1,param_2,param_3);
            if (iVar2 == 0) {
              iVar2 = FUN_80023850(1,param_1,param_2,param_3);
            }
            if (iVar2 == 0) {
              iVar2 = FUN_80023850(0,param_1,param_2,param_3);
            }
          }
          else {
            iVar2 = FUN_80023850(1,param_1,param_2,param_3);
            if (iVar2 == 0) {
              iVar2 = FUN_80023850(2,param_1,param_2,param_3);
            }
            if (iVar2 == 0) {
              iVar2 = FUN_80023850(0,param_1,param_2,param_3);
            }
          }
        }
        else {
          iVar2 = FUN_80023850(0,param_1,param_2,param_3);
          if (iVar2 == 0) {
            iVar2 = FUN_80023850(1,param_1,param_2,param_3);
          }
        }
      }
      bVar1 = false;
    }
  }
  return iVar2;
}

