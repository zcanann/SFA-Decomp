// Function: FUN_80084dc0
// Entry: 80084dc0
// Size: 608 bytes

void FUN_80084dc0(int param_1,int param_2,int param_3)

{
  char cVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_2 + 0x4c);
  *(undefined4 *)(param_1 + 0x80) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(param_1 + 0x84) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(param_1 + 0x88) = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(param_1 + 0x8c) = *(undefined4 *)(param_1 + 0x18);
  *(undefined4 *)(param_1 + 0x90) = *(undefined4 *)(param_1 + 0x1c);
  *(undefined4 *)(param_1 + 0x94) = *(undefined4 *)(param_1 + 0x20);
  if (*(code **)(param_1 + 0xbc) == (code *)0x0) {
    if (*(char *)(param_3 + 0x7b) != '\0') {
      *(undefined *)(param_3 + 0x56) = 0;
      return;
    }
    cVar1 = *(char *)(param_3 + 0x56);
    if (cVar1 < '\x04') {
      if (cVar1 != '\0') {
        if (cVar1 != '\x02') {
          *(float *)(param_3 + 0x4c) = FLOAT_803defc8;
          *(float *)(param_3 + 0x40) = *(float *)(param_1 + 0xc) - *(float *)(param_2 + 0xc);
          *(float *)(param_3 + 0x44) = *(float *)(param_1 + 0x10) - *(float *)(param_2 + 0x10);
          *(float *)(param_3 + 0x48) = *(float *)(param_1 + 0x14) - *(float *)(param_2 + 0x14);
          *(undefined *)(param_3 + 0x56) = 2;
        }
        if (*(char *)(iVar2 + 0x20) == '\x01') {
          *(float *)(param_3 + 0x24) = FLOAT_803df024;
          if ((char)(&DAT_8039a50c)[*(char *)(param_3 + 0x57)] < '\x02') {
            (&DAT_8039a50c)[*(char *)(param_3 + 0x57)] = 1;
          }
        }
        *(float *)(param_3 + 0x4c) =
             -(*(float *)(param_3 + 0x24) * FLOAT_803db414 - *(float *)(param_3 + 0x4c));
        if (*(float *)(param_3 + 0x4c) <= FLOAT_803defb0) {
          *(undefined *)(param_3 + 0x56) = 0;
        }
      }
    }
    else {
      iVar2 = FUN_80080580(param_1,param_3,6,0x1e,0x50,0xffffffff,0xffffffff);
      if ((iVar2 != 0) && ((char)(&DAT_8039a50c)[*(char *)(param_3 + 0x57)] < '\x02')) {
        (&DAT_8039a50c)[*(char *)(param_3 + 0x57)] = 1;
      }
    }
  }
  else {
    iVar2 = (**(code **)(param_1 + 0xbc))();
    if (iVar2 == 4) {
      DAT_803dd0da = 1;
    }
    else if ((iVar2 != 0) && ((char)(&DAT_8039a50c)[*(char *)(param_3 + 0x57)] < '\x02')) {
      (&DAT_8039a50c)[*(char *)(param_3 + 0x57)] = (char)iVar2;
    }
    *(undefined *)(param_3 + 0x8b) = 0;
    *(undefined *)(param_3 + 0x80) = 0;
  }
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf8;
  FUN_8000e10c(param_1,param_1 + 0x18,param_1 + 0x1c,param_1 + 0x20);
  if (*(int *)(param_1 + 0x54) != 0) {
    *(undefined4 *)(*(int *)(param_1 + 0x54) + 0x50) = 0;
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x71) = 0;
  }
  if (*(int *)(param_1 + 0x58) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x58) + 0x10f) = 0;
  }
  return;
}

