// Function: FUN_801d4f68
// Entry: 801d4f68
// Size: 524 bytes

undefined FUN_801d4f68(short *param_1,int param_2,int param_3)

{
  short sVar1;
  int iVar2;
  short sVar3;
  undefined2 uVar4;
  undefined uVar5;
  double dVar6;
  
  if (*(char *)(param_3 + 0x1b) == '\0') {
    uVar5 = 7;
  }
  else {
    iVar2 = FUN_8002b9ec();
    dVar6 = (double)FUN_8002166c(param_1 + 0xc,iVar2 + 0x18);
    if ((double)FLOAT_803e5424 <= dVar6) {
      dVar6 = (double)FUN_8002166c(param_1 + 0xc,param_3 + 8);
      if ((double)(float)((double)CONCAT44(0x43300000,
                                           (uint)*(byte *)(param_3 + 0x1b) *
                                           (uint)*(byte *)(param_3 + 0x1b) ^ 0x80000000) -
                         DOUBLE_803e5428) < dVar6) {
        sVar3 = FUN_800217c0((double)(*(float *)(param_1 + 6) - *(float *)(param_3 + 8)),
                             (double)(*(float *)(param_1 + 10) - *(float *)(param_3 + 0x10)));
        sVar1 = *param_1;
        sVar3 = sVar3 - sVar1;
        if (0x8000 < sVar3) {
          sVar3 = sVar3 + 1;
        }
        if (sVar3 < -0x8000) {
          sVar3 = sVar3 + -1;
        }
        iVar2 = (int)sVar3;
        if (iVar2 < 0) {
          iVar2 = -iVar2;
        }
        if (0x20 < iVar2) {
          uVar4 = FUN_800217c0((double)(*(float *)(param_1 + 6) - *(float *)(param_3 + 8)),
                               (double)(*(float *)(param_1 + 10) - *(float *)(param_3 + 0x10)));
          FUN_8007d6dc(s_angle__d__obj_yaw__d_80327470,uVar4,(int)sVar1);
          if (('\x01' < *(char *)(param_2 + 0x624)) && (*(char *)(param_2 + 0x624) < '\x06')) {
            return 6;
          }
          return 7;
        }
      }
      iVar2 = FUN_8005a10c((double)(*(float *)(param_1 + 0x54) * *(float *)(param_1 + 4)),
                           param_1 + 6);
      if (iVar2 == 0) {
        uVar5 = 7;
      }
      else if ((*(char *)(param_2 + 0x624) < '\x02') || ('\x05' < *(char *)(param_2 + 0x624))) {
        uVar5 = 2;
      }
      else {
        uVar5 = FUN_800221a0(3,5);
      }
    }
    else if ((*(char *)(param_2 + 0x624) < '\x02') || ('\x05' < *(char *)(param_2 + 0x624))) {
      uVar5 = 7;
    }
    else {
      uVar5 = 6;
    }
  }
  return uVar5;
}

