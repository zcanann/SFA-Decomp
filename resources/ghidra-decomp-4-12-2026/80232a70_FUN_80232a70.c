// Function: FUN_80232a70
// Entry: 80232a70
// Size: 720 bytes

void FUN_80232a70(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)

{
  double dVar1;
  int iVar2;
  undefined8 uVar3;
  undefined4 local_38;
  undefined4 uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  undefined4 local_20;
  uint uStack_1c;
  longlong local_18;
  
  if (*(int *)(param_9 + 0x54) != 0) {
    if (*(char *)(param_10 + 0x154) != '\0') {
      *(float *)(param_10 + 0x110) = *(float *)(param_10 + 0x110) - FLOAT_803dc074;
      if (*(float *)(param_10 + 0x110) <= FLOAT_803e7e00) {
        *(undefined *)(param_10 + 0x154) = 0;
      }
      dVar1 = DOUBLE_803e7e18;
      if ((*(byte *)(param_10 + 0x160) >> 4 & 1) != 0) {
        uStack_2c = (uint)*(ushort *)(param_10 + 0x150);
        local_30 = 0x43300000;
        iVar2 = (int)(FLOAT_803e7e44 * FLOAT_803dc074 +
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e7e18));
        local_28 = (longlong)iVar2;
        *(short *)(param_10 + 0x150) = (short)iVar2;
        param_2 = (double)FLOAT_803e7e48;
        uStack_1c = (uint)*(ushort *)(param_10 + 0x152);
        local_20 = 0x43300000;
        iVar2 = (int)(param_2 * (double)FLOAT_803dc074 +
                     (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - dVar1));
        local_18 = (longlong)iVar2;
        *(short *)(param_10 + 0x152) = (short)iVar2;
        param_3 = dVar1;
      }
    }
    iVar2 = FUN_80036974(param_9,&uStack_34,(int *)0x0,&local_38);
    if ((iVar2 != 0) || (*(int *)(*(int *)(param_9 + 0x54) + 0x50) != 0)) {
      if ((*(byte *)(param_10 + 0x160) >> 4 & 1) == 0) {
        if (*(char *)(param_10 + 0x154) == '\0') {
          FUN_8000b4f0(param_9,0x2b3,4);
        }
        *(float *)(param_10 + 0x110) = FLOAT_803e7e4c;
        *(undefined *)(param_10 + 0x154) = 1;
      }
      else {
        if (*(char *)(param_10 + 0x154) == '\0') {
          FUN_8000b4f0(param_9,0x29e,4);
        }
        FUN_8002ad08(param_9,0xf,200,0,0,1);
        *(float *)(param_10 + 0x110) = FLOAT_803e7e4c;
        *(undefined *)(param_10 + 0x154) = 1;
        *(undefined2 *)(param_10 + 0x150) = 0;
        *(undefined2 *)(param_10 + 0x152) = 0;
        *(char *)(param_10 + 0x15e) = *(char *)(param_10 + 0x15e) - (char)local_38;
        if (*(char *)(param_10 + 0x15e) < '\x01') {
          FUN_800803f8((undefined4 *)(param_10 + 300));
          FUN_80080404((float *)(param_10 + 300),0x78);
          if (*(char *)(param_10 + 0x15c) == '\x01') {
            FUN_8009adfc((double)FLOAT_803e7e34,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,1,0,1,1,0,0,0);
            *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
            uVar3 = FUN_80035ff8(param_9);
            *(undefined *)(param_10 + 0x159) = 4;
            *(undefined *)(param_10 + 0x159) = 3;
            if (*(char *)(param_10 + 0x15d) == '\x03') {
              FUN_80125e88(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xe);
            }
          }
          else {
            FUN_8009adfc((double)FLOAT_803e7e34,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,1,0,0,1,0,0,3);
            *(ushort *)(param_9 + 6) = *(ushort *)(param_9 + 6) | 0x4000;
            FUN_80035ff8(param_9);
            *(undefined *)(param_10 + 0x159) = 3;
          }
          iVar2 = FUN_8022de2c();
          if (iVar2 != 0) {
            FUN_8022dbe4(iVar2,(ushort)*(byte *)(param_10 + 0x157));
          }
        }
        else {
          iVar2 = FUN_8022de2c();
          if (iVar2 != 0) {
            FUN_8022dbe4(iVar2,(ushort)*(byte *)(param_10 + 0x158));
          }
        }
      }
    }
  }
  return;
}

