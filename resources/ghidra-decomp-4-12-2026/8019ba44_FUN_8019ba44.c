// Function: FUN_8019ba44
// Entry: 8019ba44
// Size: 3800 bytes

undefined4
FUN_8019ba44(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,
            undefined4 param_10,undefined4 param_11,float *param_12,int param_13,undefined4 param_14
            ,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  char cVar2;
  int iVar3;
  uint uVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined auStack_44 [27];
  undefined local_29;
  undefined4 local_28;
  uint uStack_24;
  undefined8 local_20;
  
  local_54 = FLOAT_803e4dc4;
  local_58 = FLOAT_803e4dc8;
  iVar6 = *(int *)(param_9 + 0x26);
  local_29 = 0;
  iVar7 = *(int *)(param_9 + 0x5c);
  *(byte *)(iVar7 + 0xa9b) = *(byte *)(iVar7 + 0xa9b) & 0xfd;
  *(float *)(iVar7 + 0x7fc) = FLOAT_803e4dcc;
  iVar3 = FUN_8002bac4();
  FUN_80037afc((int)param_9);
  if ((*(char *)(iVar6 + 0x19) == '\x01') && (uVar4 = FUN_80020078(0x57), uVar4 == 0)) {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
  }
  else {
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    fVar1 = FLOAT_803e4da8;
    switch(*(undefined *)(iVar7 + 0xa80)) {
    case 0:
      if (*(char *)(iVar7 + 0xa98) == '\x02') {
        *(undefined *)(iVar7 + 0xa98) = 1;
      }
      uVar4 = FUN_80020078(0x94f);
      if (uVar4 != 0) {
        *(undefined *)(iVar7 + 0xa80) = 1;
      }
      break;
    case 1:
      if (*(char *)(iVar7 + 0xa98) == '\x02') {
        *(undefined *)(iVar7 + 0xa98) = 1;
      }
      uVar4 = FUN_80020078(0x4e);
      if (uVar4 != 0) {
        *(undefined *)(iVar7 + 0xa80) = 3;
        FUN_8003042c((double)FLOAT_803e4da8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x1a,0,param_12,param_13,param_14,param_15,param_16);
        param_9[0x7a] = 0;
        param_9[0x7b] = 0;
        FUN_800201ac(0x48,1);
        *(byte *)(iVar7 + 0xa9b) = *(byte *)(iVar7 + 0xa9b) | 1;
      }
      break;
    case 2:
      if (*(char *)(iVar7 + 0xa98) == '\x02') {
        *(undefined *)(iVar7 + 0xa98) = 1;
      }
      *(byte *)(iVar7 + 0xa9b) = *(byte *)(iVar7 + 0xa9b) | 2;
      param_12 = (float *)(iVar7 + 0x7fc);
      iVar6 = FUN_8019b4e0((double)FLOAT_803e4dd0,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,iVar7 + 0x6bc,0,param_12,param_13,param_14,param_15,
                           param_16);
      if (iVar6 != 0) {
        *(byte *)(iVar7 + 0xa9b) = *(byte *)(iVar7 + 0xa9b) & 0xfe;
        *(undefined *)(iVar7 + 0xa80) = 4;
      }
      break;
    case 3:
      param_12 = (float *)*DAT_803dd6d4;
      (*(code *)param_12[0x12])(2,param_9,0xffffffff);
      FUN_800201ac(0x60,1);
      *(undefined *)(iVar7 + 0xa80) = 2;
      break;
    case 4:
      uVar4 = FUN_80020078(0x57);
      if (uVar4 == 0) {
        if (*(char *)(iVar7 + 0xa98) == '\x02') {
          *(undefined *)(iVar7 + 0xa98) = 1;
          iVar6 = *(char *)(iVar7 + 0xa99) + 1;
          cVar2 = (char)(iVar6 >> 0x1f);
          *(byte *)(iVar7 + 0xa99) = ((byte)iVar6 & 1 ^ -cVar2) + cVar2;
        }
      }
      else if (*(char *)(iVar6 + 0x19) == '\x01') {
        *(undefined *)(iVar7 + 0xa80) = 0xe;
        *(undefined *)(iVar7 + 0xa99) = 0;
      }
      else {
        *(undefined *)(iVar7 + 0xa80) = 0xf;
        *(undefined *)(iVar7 + 0xa99) = 0;
      }
      break;
    case 6:
      if (*(int *)(iVar7 + 0xa94) == 0) {
        if (*(char *)(iVar7 + 0xa98) == '\x02') {
          *(undefined *)(iVar7 + 0xa98) = 1;
        }
      }
      else {
        if (*(int *)(iVar7 + 0xa94) < 2) {
          param_2 = (double)(FLOAT_803e4ddc * *(float *)(param_9 + 0x14));
          if (param_2 < (double)FLOAT_803e4da8) {
            param_2 = -param_2;
          }
          uStack_24 = (int)*param_9 ^ 0x80000000;
          local_28 = 0x43300000;
          iVar6 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4db0) +
                       param_2);
          local_20 = (double)(longlong)iVar6;
          *param_9 = (short)iVar6;
          *(float *)(iVar7 + 0x7fc) = FLOAT_803e4de0;
          uVar4 = FUN_80020078(0x8e9);
          if (uVar4 != 0) {
            FUN_8003042c((double)FLOAT_803e4da8,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,0,0,param_12,param_13,param_14,param_15,param_16);
            FUN_8002f66c((int)param_9,0x32);
            *(float *)(param_9 + 0x14) = FLOAT_803e4da8;
            FUN_8003709c((int)param_9,0x16);
            fVar1 = FLOAT_803e4da8;
            *(float *)(param_9 + 0x12) = FLOAT_803e4da8;
            *(float *)(param_9 + 0x14) = FLOAT_803e4de4;
            *(float *)(param_9 + 0x16) = fVar1;
            *(undefined4 *)(iVar7 + 0xa94) = 2;
            *(byte *)(iVar7 + 0xa9b) = *(byte *)(iVar7 + 0xa9b) & 0xfe;
          }
        }
        else {
          *(float *)(param_9 + 0x12) = FLOAT_803e4da8;
          *(float *)(param_9 + 0x16) = fVar1;
          *(float *)(param_9 + 8) =
               *(float *)(param_9 + 0x14) * FLOAT_803dc074 + *(float *)(param_9 + 8);
          param_2 = (double)*(float *)(param_9 + 8);
          param_3 = (double)*(float *)(param_9 + 10);
          FUN_80065a20((double)*(float *)(param_9 + 6),param_2,param_3,param_9,&local_58,0);
          *param_9 = (short)((0xc0 << *param_9 + 8) >> 1);
          *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
               *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfbff;
          if (FLOAT_803e4dc8 < local_58) {
            *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x14) - FLOAT_803e4dd8;
          }
          else {
            *(undefined4 *)(iVar7 + 0xa94) = 2;
            *(float *)(param_9 + 8) = *(float *)(param_9 + 8) - local_58;
            *(undefined *)(iVar7 + 0xa98) = 1;
            param_9[0x7a] = 0;
            param_9[0x7b] = 0;
            FUN_8003042c((double)FLOAT_803e4da8,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,0,0,param_12,param_13,param_14,param_15,param_16);
            param_12 = (float *)0x2;
            iVar6 = FUN_8019b974((int)param_9,0,(undefined4 *)0x0,2);
            *(undefined4 *)(iVar7 + 0xa74) = *(undefined4 *)(iVar6 + 8);
            *(undefined4 *)(iVar7 + 0xa78) = *(undefined4 *)(iVar6 + 0xc);
            *(undefined4 *)(iVar7 + 0xa7c) = *(undefined4 *)(iVar6 + 0x10);
            *(short *)(iVar7 + 0xa68) = (short)((int)*(char *)(iVar6 + 0x2c) << 8);
            fVar1 = *(float *)(iVar7 + 0xa78) - *(float *)(param_9 + 8);
            if (fVar1 < FLOAT_803e4da8) {
              fVar1 = -fVar1;
            }
            if (fVar1 < FLOAT_803e4dd4) {
              FUN_800372f8((int)param_9,0x16);
              *(undefined *)(iVar7 + 0xa80) = 7;
              FUN_8003042c((double)FLOAT_803e4da8,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,0x1a,0,param_12,param_13,param_14,param_15,param_16);
            }
          }
        }
        if (*(int *)(iVar7 + 0xa94) < 2) {
          *(float *)(param_9 + 6) =
               FLOAT_803dc074 * *(float *)(param_9 + 0x12) + *(float *)(param_9 + 6);
          *(float *)(param_9 + 10) =
               FLOAT_803dc074 * *(float *)(param_9 + 0x16) + *(float *)(param_9 + 10);
          fVar1 = FLOAT_803e4de8;
          if (*(char *)(iVar7 + 0xa5e) != '\0') {
            *(float *)(param_9 + 0x12) = FLOAT_803e4de8 * -*(float *)(param_9 + 0x12);
            *(float *)(param_9 + 0x16) = fVar1 * -*(float *)(param_9 + 0x16);
          }
          param_4 = (double)(*(float *)(param_9 + 10) - *(float *)(param_9 + 0x44));
          dVar8 = (double)(FLOAT_803e4dec * FLOAT_803dc078);
          local_50 = (float)((double)(*(float *)(param_9 + 6) - *(float *)(param_9 + 0x40)) * dVar8)
          ;
          param_3 = (double)local_50;
          local_4c = (float)((double)(*(float *)(param_9 + 8) - *(float *)(param_9 + 0x42)) * dVar8)
          ;
          param_2 = (double)local_4c;
          local_48 = (float)(param_4 * dVar8);
          *(float *)(param_9 + 0x12) = (float)(param_3 + (double)*(float *)(param_9 + 0x12));
          *(float *)(param_9 + 0x14) = (float)(param_2 + (double)*(float *)(param_9 + 0x14));
          *(float *)(param_9 + 0x16) = local_48 + *(float *)(param_9 + 0x16);
          fVar1 = FLOAT_803e4dd0;
          *(float *)(param_9 + 0x12) = FLOAT_803e4dd0 * *(float *)(param_9 + 0x12);
          *(float *)(param_9 + 0x14) = fVar1 * *(float *)(param_9 + 0x14);
          *(float *)(param_9 + 0x16) = fVar1 * *(float *)(param_9 + 0x16);
        }
      }
      break;
    case 7:
      if (*(char *)(iVar7 + 0xa98) == '\x02') {
        *(undefined *)(iVar7 + 0xa98) = 1;
      }
      *(byte *)(iVar7 + 0xa9b) = *(byte *)(iVar7 + 0xa9b) | 2;
      param_12 = (float *)(iVar7 + 0x7fc);
      iVar6 = FUN_8019b4e0((double)FLOAT_803e4dd0,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,iVar7 + 0x6bc,1,param_12,param_13,param_14,param_15,
                           param_16);
      if (iVar6 != 0) {
        *(undefined *)(iVar7 + 0xa80) = 8;
        FUN_8002f66c((int)param_9,0x32);
      }
      break;
    case 8:
      iVar6 = FUN_80036f50(3,param_9,&local_54);
      if ((iVar6 != 0) && (local_54 < FLOAT_803e4df0)) {
        FUN_80115328(iVar7,iVar6);
        *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 0x10;
      }
      if ((local_54 <= FLOAT_803e4df0) ||
         (dVar8 = (double)FUN_80021754((float *)(iVar3 + 0x18),(float *)(param_9 + 0xc)),
         (double)FLOAT_803e4dd4 <= dVar8)) {
        if (((*(byte *)(iVar7 + 0xa9b) & 4) == 0) &&
           (*(int *)(&DAT_803235a4 + (uint)*(byte *)(iVar7 + 0xa80) * 4) != 0xe)) {
          *(undefined *)(iVar7 + 0xa98) = 2;
          *(byte *)(iVar7 + 0xa9b) = *(byte *)(iVar7 + 0xa9b) | 5;
          FUN_80114420(0xe,(undefined2 *)(iVar7 + 0xa68));
          *(undefined4 *)(&DAT_803235a4 + (uint)*(byte *)(iVar7 + 0xa80) * 4) = 0xe;
        }
      }
      else {
        *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xef;
        if (((*(byte *)(iVar7 + 0xa9b) & 4) == 0) &&
           (*(int *)(&DAT_803235a4 + (uint)*(byte *)(iVar7 + 0xa80) * 4) != 0)) {
          FUN_80114320(0xf,(undefined2 *)(iVar7 + 0xa68));
          *(byte *)(iVar7 + 0xa9b) = *(byte *)(iVar7 + 0xa9b) | 5;
          *(undefined4 *)(&DAT_803235a4 + (uint)*(byte *)(iVar7 + 0xa80) * 4) = 0;
        }
        if (*(char *)(iVar7 + 0xa98) == '\x02') {
          *(undefined *)(iVar7 + 0xa98) = 1;
          iVar6 = *(char *)(iVar7 + 0xa99) + 1;
          cVar2 = (char)(iVar6 >> 0x1f);
          *(byte *)(iVar7 + 0xa99) = ((byte)iVar6 & 1 ^ -cVar2) + cVar2;
        }
      }
      if (((*(byte *)(iVar7 + 0xa9b) & 4) != 0) &&
         (iVar6 = FUN_8019b754((double)FLOAT_803e4dc0,param_9,(short *)(iVar7 + 0xa68),
                               (float *)(iVar7 + 0x7fc),param_12,param_13,param_14,param_15,param_16
                              ), iVar6 != 0)) {
        FUN_8003042c((double)FLOAT_803e4da8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x1a,0,param_12,param_13,param_14,param_15,param_16);
        *(byte *)(iVar7 + 0xa9b) = *(byte *)(iVar7 + 0xa9b) & 0xfa;
      }
      uVar4 = FUN_80020078(0x43);
      if (uVar4 != 0) {
        *(undefined *)(iVar7 + 0xa80) = 9;
        *(undefined *)(iVar7 + 0xa99) = 0;
      }
      break;
    case 9:
      iVar6 = FUN_80036f50(3,param_9,&local_54);
      if ((iVar6 != 0) && (local_54 < FLOAT_803e4df0)) {
        FUN_80115328(iVar7,iVar6);
      }
      if ((local_54 <= FLOAT_803e4df0) ||
         (dVar8 = (double)FUN_80021754((float *)(iVar3 + 0x18),(float *)(param_9 + 0xc)),
         (double)FLOAT_803e4dd4 <= dVar8)) {
        if (((*(byte *)(iVar7 + 0xa9b) & 4) == 0) &&
           (*(int *)(&DAT_803235a4 + (uint)*(byte *)(iVar7 + 0xa80) * 4) != 0xe)) {
          *(undefined *)(iVar7 + 0xa98) = 2;
          *(byte *)(iVar7 + 0xa9b) = *(byte *)(iVar7 + 0xa9b) | 5;
          FUN_80114420(0xe,(undefined2 *)(iVar7 + 0xa68));
          *(undefined4 *)(&DAT_803235a4 + (uint)*(byte *)(iVar7 + 0xa80) * 4) = 0xe;
        }
      }
      else {
        if (((*(byte *)(iVar7 + 0xa9b) & 4) == 0) &&
           (*(int *)(&DAT_803235a4 + (uint)*(byte *)(iVar7 + 0xa80) * 4) != 0)) {
          FUN_80114320(0xf,(undefined2 *)(iVar7 + 0xa68));
          *(byte *)(iVar7 + 0xa9b) = *(byte *)(iVar7 + 0xa9b) | 5;
          *(undefined4 *)(&DAT_803235a4 + (uint)*(byte *)(iVar7 + 0xa80) * 4) = 0;
        }
        if (*(char *)(iVar7 + 0xa98) == '\x02') {
          *(undefined *)(iVar7 + 0xa98) = 1;
          iVar6 = *(char *)(iVar7 + 0xa99) + 1;
          cVar2 = (char)(iVar6 >> 0x1f);
          *(byte *)(iVar7 + 0xa99) = ((byte)iVar6 & 1 ^ -cVar2) + cVar2;
        }
      }
      if (((*(byte *)(iVar7 + 0xa9b) & 4) != 0) &&
         (iVar6 = FUN_8019b754((double)FLOAT_803e4dc0,param_9,(short *)(iVar7 + 0xa68),
                               (float *)(iVar7 + 0x7fc),param_12,param_13,param_14,param_15,param_16
                              ), iVar6 != 0)) {
        FUN_8003042c((double)FLOAT_803e4da8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x1a,0,param_12,param_13,param_14,param_15,param_16);
        *(byte *)(iVar7 + 0xa9b) = *(byte *)(iVar7 + 0xa9b) & 0xfa;
      }
      uVar4 = FUN_80020078(0x4be);
      if (uVar4 != 0) {
        *(undefined *)(iVar7 + 0xa80) = 10;
        FUN_8003042c((double)FLOAT_803e4da8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0x1a,0,param_12,param_13,param_14,param_15,param_16);
        param_9[0x7a] = 0;
        param_9[0x7b] = 0;
      }
      break;
    case 10:
      if (*(char *)(iVar7 + 0xa98) == '\x02') {
        *(undefined *)(iVar7 + 0xa98) = 1;
      }
      *(byte *)(iVar7 + 0xa9b) = *(byte *)(iVar7 + 0xa9b) | 2;
      param_12 = (float *)(iVar7 + 0x7fc);
      iVar6 = FUN_8019b4e0((double)FLOAT_803e4df4,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,iVar7 + 0x6bc,2,param_12,param_13,param_14,param_15,
                           param_16);
      if (iVar6 != 0) {
        *(undefined *)(iVar7 + 0xa80) = 0xb;
      }
      break;
    case 0xb:
      if (*(char *)(iVar7 + 0xa98) == '\x02') {
        *(undefined *)(iVar7 + 0xa98) = 1;
      }
      *(undefined *)(param_9 + 0x1b) = 0;
      *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
      FUN_8002cf80((int)param_9);
      param_9[3] = param_9[3] | 0x4000;
      *(undefined *)(iVar7 + 0xa80) = 0xf;
      break;
    case 0xc:
      if (*(char *)(iVar7 + 0xa98) == '\x02') {
        *(undefined *)(iVar7 + 0xa98) = 1;
      }
      uVar4 = FUN_80020078(0x4b7);
      if (uVar4 != 0) {
        (**(code **)(*DAT_803dd6d0 + 0x48))(param_9);
        param_12 = (float *)*DAT_803dd6d4;
        (*(code *)param_12[0x12])(0xb,param_9,0xffffffff);
        FUN_800201ac(0x4b7,0);
      }
      uVar4 = FUN_80020078(0x49a);
      if (uVar4 != 0) {
        *(undefined *)(iVar7 + 0xa80) = 0xd;
      }
      break;
    case 0xd:
      if (*(char *)(iVar7 + 0xa98) == '\x02') {
        *(undefined *)(iVar7 + 0xa98) = 1;
      }
      uVar4 = FUN_80020078(0x4b7);
      if (uVar4 != 0) {
        (**(code **)(*DAT_803dd6d0 + 0x48))(param_9);
        param_12 = (float *)*DAT_803dd6d4;
        (*(code *)param_12[0x12])(10,param_9,0xffffffff);
        FUN_800201ac(0x4b7,0);
      }
      uVar4 = FUN_80020078(0x4aa);
      if (uVar4 != 0) {
        *(undefined *)(iVar7 + 0xa80) = 0xe;
      }
      break;
    case 0xe:
      if (*(char *)(iVar7 + 0xa98) == '\x02') {
        *(undefined *)(iVar7 + 0xa98) = 1;
      }
      break;
    case 0xf:
      param_9[3] = param_9[3] | 0x4000;
      FUN_8002cf80((int)param_9);
      *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) & 0xfffe;
    }
    FUN_80115330();
    iVar6 = FUN_8003811c((int)param_9);
    if (iVar6 != 0) {
      FUN_80014b68(0,0x100);
      iVar6 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x2e8);
      if (iVar6 == 0) {
        if (*(char *)(iVar7 + 0xa98) == '\x01') {
          piVar5 = (int *)FUN_80080284((int *)&DAT_8032349c,0xf,(uint)*(byte *)(iVar7 + 0xa80));
          iVar3 = FUN_80297174(iVar3);
          if (iVar3 < 4) {
            iVar3 = piVar5[1];
          }
          else {
            iVar3 = *piVar5;
          }
          uVar4 = (uint)(int)*(char *)(iVar7 + 0xa9a) >> 0x1f;
          if ((((int)*(char *)(iVar7 + 0xa9a) & 1U ^ uVar4) != uVar4) && (piVar5[2] != -1)) {
            iVar3 = piVar5[2];
          }
          *(char *)(iVar7 + 0xa9a) = *(char *)(iVar7 + 0xa9a) + '\x01';
          if (iVar3 != -1) {
            *(undefined *)(iVar7 + 0xa98) = 2;
            param_12 = (float *)*DAT_803dd6d4;
            (*(code *)param_12[0x12])(iVar3,param_9,0xffffffff);
          }
        }
      }
      else {
        FUN_800201ac(0x4ab,1);
      }
    }
    uVar4 = FUN_80020078(0x902);
    if ((uVar4 != 0) &&
       (piVar5 = (int *)FUN_80080284((int *)&DAT_8032349c,0xf,(uint)*(byte *)(iVar7 + 0xa80)),
       *piVar5 != -1)) {
      *(undefined *)(iVar7 + 0xa98) = 2;
      param_12 = (float *)*DAT_803dd6d4;
      (*(code *)param_12[0x12])(*piVar5,param_9,0xffffffff);
      FUN_800201ac(0x902,0);
    }
    iVar3 = *(int *)(&DAT_803235a4 + (uint)*(byte *)(iVar7 + 0xa80) * 4);
    if (((iVar3 != -1) && ((*(byte *)(iVar7 + 0xa9b) & 1) == 0)) && (param_9[0x50] != iVar3)) {
      FUN_8003042c((double)FLOAT_803e4da8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,iVar3,0,param_12,param_13,param_14,param_15,param_16);
      FUN_8002f66c((int)param_9,0x50);
    }
    local_20 = (double)CONCAT44(0x43300000,(uint)DAT_803dc070);
    iVar3 = FUN_8002fb40((double)*(float *)(iVar7 + 0x7fc),
                         (double)(float)(local_20 - DOUBLE_803e4df8));
    if (((iVar3 != 0) && ((*(byte *)(iVar7 + 0xa9b) & 1) != 0)) &&
       ((param_9[0x50] != 0x1a && (param_9[0x50] != 9)))) {
      *(byte *)(iVar7 + 0xa9b) = *(byte *)(iVar7 + 0xa9b) & 0xfe;
    }
    FUN_8019b3b8(param_9,auStack_44,(ushort *)&DAT_803dca88);
    uVar4 = FUN_8008038c(0x3c);
    if (uVar4 != 0) {
      FUN_800394f0(param_9,iVar7 + 0x624,0xdf,0x1000,0xffffffff,0);
    }
    FUN_80039030((int)param_9,(char *)(iVar7 + 0x624));
    FUN_8003b408((int)param_9,iVar7 + 0x654);
    uVar4 = FUN_80020078(0x4b);
    if (*(byte *)(iVar7 + 0xa80) != uVar4) {
      FUN_800201ac(0x4b,(uint)*(byte *)(iVar7 + 0xa80));
    }
  }
  return 0;
}

