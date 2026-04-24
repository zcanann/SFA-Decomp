// Function: FUN_802b78a4
// Entry: 802b78a4
// Size: 616 bytes

/* WARNING: Removing unreachable block (ram,0x802b7ae4) */

undefined4 FUN_802b78a4(undefined8 param_1,short *param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined8 in_f31;
  double local_38;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar2 = *(int *)(param_2 + 0x5c);
  iVar3 = *(int *)(iVar2 + 0x40c);
  if (*(float *)(iVar3 + 0x14) <= FLOAT_803e8180) {
    FUN_8000bb18(param_2,0x4be);
    uVar1 = FUN_800221a0(0x78,0xb4);
    local_38 = (double)CONCAT44(0x43300000,uVar1 ^ 0x80000000);
    *(float *)(iVar3 + 0x14) = (float)(local_38 - DOUBLE_803e8198);
  }
  local_38 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0x22));
  *(float *)(param_3 + 0x2a0) =
       FLOAT_803e8184 *
       (FLOAT_803e8188 -
       (float)(local_38 - DOUBLE_803e81a0) /
       (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar2 + 0x3fe)) - DOUBLE_803e81a0));
  if (*(float *)(param_3 + 0x2a0) < FLOAT_803e818c) {
    *(float *)(param_3 + 0x2a0) = FLOAT_803e818c;
  }
  if ((*(char *)(param_3 + 0x27a) != '\0') || (*(char *)(param_3 + 0x346) != '\0')) {
    if (*(char *)(iVar3 + 0x2c) == '\0') {
      uVar1 = (**(code **)(*DAT_803dcab8 + 0x18))((double)FLOAT_803e8190,param_2,param_3);
      if ((uVar1 & 1) == 0) {
        if ((uVar1 & 4) == 0) {
          if ((uVar1 & 2) == 0) {
            if ((uVar1 & 8) != 0) {
              *param_2 = *param_2 + 0x3ffc;
              *(undefined *)(iVar3 + 0x2c) = 3;
            }
          }
          else {
            *param_2 = *param_2 + -0x3ffc;
            *(undefined *)(iVar3 + 0x2c) = 3;
          }
        }
        else {
          *param_2 = *param_2 + 0x7ff8;
          *(undefined *)(iVar3 + 0x2c) = 3;
        }
      }
    }
    else {
      *(char *)(iVar3 + 0x2c) = *(char *)(iVar3 + 0x2c) + -1;
    }
    FUN_80030334((double)FLOAT_803e8180,param_2,0x14,0);
  }
  if (*(char *)(iVar3 + 0x2c) == '\0') {
    *param_2 = *param_2 +
               (short)(int)((float)((double)CONCAT44(0x43300000,
                                                     *(ushort *)(iVar3 + 0x20) - 0x7fff ^ 0x80000000
                                                    ) - DOUBLE_803e8198) * FLOAT_803db414 *
                           FLOAT_803e8194);
  }
  (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,1);
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return 0;
}

