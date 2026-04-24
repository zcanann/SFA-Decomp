// Function: FUN_80297854
// Entry: 80297854
// Size: 636 bytes

/* WARNING: Removing unreachable block (ram,0x80297aac) */

int FUN_80297854(undefined8 param_1,undefined2 *param_2,int param_3)

{
  undefined2 uVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 uVar6;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar5 = *(int *)(param_2 + 0x5c);
  if (*(char *)(param_3 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e7ea4,param_2,(int)*(short *)(&DAT_803336bc + DAT_80333be6 * 2),0)
    ;
    *(float *)(param_3 + 0x2a0) = FLOAT_803e7f0c;
    fVar2 = FLOAT_803e7ea4;
    *(float *)(param_3 + 0x294) = FLOAT_803e7ea4;
    *(float *)(param_3 + 0x284) = fVar2;
    *(float *)(param_3 + 0x280) = fVar2;
    *(float *)(param_2 + 0x12) = fVar2;
    *(float *)(param_2 + 0x14) = fVar2;
    *(float *)(param_2 + 0x16) = fVar2;
  }
  iVar3 = FUN_8029b9fc(param_1,param_2,param_3);
  if (iVar3 == 0) {
    (**(code **)(*DAT_803dca8c + 0x30))(param_1,param_2,param_3,0x10);
    uVar1 = *param_2;
    *(undefined2 *)(iVar5 + 0x484) = uVar1;
    *(undefined2 *)(iVar5 + 0x478) = uVar1;
    (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,1);
    if ((*(uint *)(param_3 + 0x314) & 0x200) != 0) {
      FUN_80014aa0((double)FLOAT_803e7f10);
      FUN_8000bb18(param_2,0x3cd);
      *(ushort *)(iVar5 + 0x8d8) = *(ushort *)(iVar5 + 0x8d8) | 4;
    }
    if (((*(byte *)(param_3 + 0x356) & 1) == 0) && (FLOAT_803e7f14 < *(float *)(param_2 + 0x4c))) {
      FUN_8000bb18(param_2,0x1b);
      *(byte *)(param_3 + 0x356) = *(byte *)(param_3 + 0x356) | 1;
    }
    if (((*(byte *)(param_3 + 0x356) & 2) == 0) && (FLOAT_803e7f18 < *(float *)(param_2 + 0x4c))) {
      uVar4 = FUN_8006ed24(*(undefined *)(iVar5 + 0x86c),*(undefined *)(iVar5 + 0x8a5));
      FUN_8000bb18(param_2,uVar4);
      *(byte *)(param_3 + 0x356) = *(byte *)(param_3 + 0x356) | 2;
    }
    if (*(char *)(param_3 + 0x346) == '\0') {
      if (FLOAT_803e7f1c < *(float *)(param_2 + 0x4c)) {
        if (*(char *)(param_3 + 0x349) != '\x01') {
          if ((DAT_803de44c != 0) && ((*(byte *)(iVar5 + 0x3f4) >> 6 & 1) != 0)) {
            *(undefined *)(iVar5 + 0x8b4) = 0;
            *(byte *)(iVar5 + 0x3f4) = *(byte *)(iVar5 + 0x3f4) & 0xf7;
          }
          *(code **)(param_3 + 0x308) = FUN_802a514c;
          iVar3 = -1;
          goto LAB_80297aac;
        }
        iVar3 = FUN_80299e44(param_1,param_2,param_3);
        if (iVar3 != 0) goto LAB_80297aac;
      }
      iVar3 = 0;
    }
    else {
      *(code **)(param_3 + 0x308) = FUN_8029c8c8;
      iVar3 = 0x25;
    }
  }
LAB_80297aac:
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  return iVar3;
}

