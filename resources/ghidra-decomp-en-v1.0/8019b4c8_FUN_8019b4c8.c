// Function: FUN_8019b4c8
// Entry: 8019b4c8
// Size: 3800 bytes

undefined4 FUN_8019b4c8(short *param_1)

{
  float fVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  undefined auStack68 [27];
  undefined local_29;
  undefined4 local_28;
  uint uStack36;
  double local_20;
  
  local_54 = FLOAT_803e412c;
  local_58 = FLOAT_803e4130;
  iVar7 = *(int *)(param_1 + 0x26);
  local_29 = 0;
  iVar8 = *(int *)(param_1 + 0x5c);
  *(byte *)(iVar8 + 0xa9b) = *(byte *)(iVar8 + 0xa9b) & 0xfd;
  *(float *)(iVar8 + 0x7fc) = FLOAT_803e4134;
  iVar3 = FUN_8002b9ec();
  FUN_80037a04(param_1);
  if ((*(char *)(iVar7 + 0x19) == '\x01') && (iVar4 = FUN_8001ffb4(0x57), iVar4 == 0)) {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
  }
  else {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xf7;
    fVar1 = FLOAT_803e4110;
    switch(*(undefined *)(iVar8 + 0xa80)) {
    case 0:
      if (*(char *)(iVar8 + 0xa98) == '\x02') {
        *(undefined *)(iVar8 + 0xa98) = 1;
      }
      iVar7 = FUN_8001ffb4(0x94f);
      if (iVar7 != 0) {
        *(undefined *)(iVar8 + 0xa80) = 1;
      }
      break;
    case 1:
      if (*(char *)(iVar8 + 0xa98) == '\x02') {
        *(undefined *)(iVar8 + 0xa98) = 1;
      }
      iVar7 = FUN_8001ffb4(0x4e);
      if (iVar7 != 0) {
        *(undefined *)(iVar8 + 0xa80) = 3;
        FUN_80030334((double)FLOAT_803e4110,param_1,0x1a,0);
        *(undefined4 *)(param_1 + 0x7a) = 0;
        FUN_800200e8(0x48,1);
        *(byte *)(iVar8 + 0xa9b) = *(byte *)(iVar8 + 0xa9b) | 1;
      }
      break;
    case 2:
      if (*(char *)(iVar8 + 0xa98) == '\x02') {
        *(undefined *)(iVar8 + 0xa98) = 1;
      }
      *(byte *)(iVar8 + 0xa9b) = *(byte *)(iVar8 + 0xa9b) | 2;
      iVar7 = FUN_8019af64((double)FLOAT_803e4138,param_1,iVar8 + 0x6bc,0,iVar8 + 0x7fc);
      if (iVar7 != 0) {
        *(byte *)(iVar8 + 0xa9b) = *(byte *)(iVar8 + 0xa9b) & 0xfe;
        *(undefined *)(iVar8 + 0xa80) = 4;
      }
      break;
    case 3:
      (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
      FUN_800200e8(0x60,1);
      *(undefined *)(iVar8 + 0xa80) = 2;
      break;
    case 4:
      iVar4 = FUN_8001ffb4(0x57);
      if (iVar4 == 0) {
        if (*(char *)(iVar8 + 0xa98) == '\x02') {
          *(undefined *)(iVar8 + 0xa98) = 1;
          iVar7 = *(char *)(iVar8 + 0xa99) + 1;
          cVar2 = (char)(iVar7 >> 0x1f);
          *(byte *)(iVar8 + 0xa99) = ((byte)iVar7 & 1 ^ -cVar2) + cVar2;
        }
      }
      else if (*(char *)(iVar7 + 0x19) == '\x01') {
        *(undefined *)(iVar8 + 0xa80) = 0xe;
        *(undefined *)(iVar8 + 0xa99) = 0;
      }
      else {
        *(undefined *)(iVar8 + 0xa80) = 0xf;
        *(undefined *)(iVar8 + 0xa99) = 0;
      }
      break;
    case 6:
      if (*(int *)(iVar8 + 0xa94) == 0) {
        if (*(char *)(iVar8 + 0xa98) == '\x02') {
          *(undefined *)(iVar8 + 0xa98) = 1;
        }
      }
      else {
        if (*(int *)(iVar8 + 0xa94) < 2) {
          fVar1 = FLOAT_803e4144 * *(float *)(param_1 + 0x14);
          if (fVar1 < FLOAT_803e4110) {
            fVar1 = -fVar1;
          }
          uStack36 = (int)*param_1 ^ 0x80000000;
          local_28 = 0x43300000;
          iVar7 = (int)((float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e4118) + fVar1);
          local_20 = (double)(longlong)iVar7;
          *param_1 = (short)iVar7;
          *(float *)(iVar8 + 0x7fc) = FLOAT_803e4148;
          iVar7 = FUN_8001ffb4(0x8e9);
          if (iVar7 != 0) {
            FUN_80030334((double)FLOAT_803e4110,param_1,0,0);
            FUN_8002f574(param_1,0x32);
            *(float *)(param_1 + 0x14) = FLOAT_803e4110;
            FUN_80036fa4(param_1,0x16);
            fVar1 = FLOAT_803e4110;
            *(float *)(param_1 + 0x12) = FLOAT_803e4110;
            *(float *)(param_1 + 0x14) = FLOAT_803e414c;
            *(float *)(param_1 + 0x16) = fVar1;
            *(undefined4 *)(iVar8 + 0xa94) = 2;
            *(byte *)(iVar8 + 0xa9b) = *(byte *)(iVar8 + 0xa9b) & 0xfe;
          }
        }
        else {
          *(float *)(param_1 + 0x12) = FLOAT_803e4110;
          *(float *)(param_1 + 0x16) = fVar1;
          *(float *)(param_1 + 8) =
               *(float *)(param_1 + 0x14) * FLOAT_803db414 + *(float *)(param_1 + 8);
          FUN_800658a4((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                       (double)*(float *)(param_1 + 10),param_1,&local_58,0);
          *param_1 = (short)((0xc0 << *param_1 + 8) >> 1);
          *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
               *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfbff;
          if (FLOAT_803e4130 < local_58) {
            *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) - FLOAT_803e4140;
          }
          else {
            *(undefined4 *)(iVar8 + 0xa94) = 2;
            *(float *)(param_1 + 8) = *(float *)(param_1 + 8) - local_58;
            *(undefined *)(iVar8 + 0xa98) = 1;
            *(undefined4 *)(param_1 + 0x7a) = 0;
            FUN_80030334((double)FLOAT_803e4110,param_1,0,0);
            iVar7 = FUN_8019b3f8(param_1,0,0,2);
            *(undefined4 *)(iVar8 + 0xa74) = *(undefined4 *)(iVar7 + 8);
            *(undefined4 *)(iVar8 + 0xa78) = *(undefined4 *)(iVar7 + 0xc);
            *(undefined4 *)(iVar8 + 0xa7c) = *(undefined4 *)(iVar7 + 0x10);
            *(short *)(iVar8 + 0xa68) = (short)((int)*(char *)(iVar7 + 0x2c) << 8);
            fVar1 = *(float *)(iVar8 + 0xa78) - *(float *)(param_1 + 8);
            if (fVar1 < FLOAT_803e4110) {
              fVar1 = -fVar1;
            }
            if (fVar1 < FLOAT_803e413c) {
              FUN_80037200(param_1,0x16);
              *(undefined *)(iVar8 + 0xa80) = 7;
              FUN_80030334((double)FLOAT_803e4110,param_1,0x1a,0);
            }
          }
        }
        if (*(int *)(iVar8 + 0xa94) < 2) {
          *(float *)(param_1 + 6) =
               FLOAT_803db414 * *(float *)(param_1 + 0x12) + *(float *)(param_1 + 6);
          *(float *)(param_1 + 10) =
               FLOAT_803db414 * *(float *)(param_1 + 0x16) + *(float *)(param_1 + 10);
          fVar1 = FLOAT_803e4150;
          if (*(char *)(iVar8 + 0xa5e) != '\0') {
            *(float *)(param_1 + 0x12) = FLOAT_803e4150 * -*(float *)(param_1 + 0x12);
            *(float *)(param_1 + 0x16) = fVar1 * -*(float *)(param_1 + 0x16);
          }
          local_48 = FLOAT_803e4154 * FLOAT_803db418;
          local_50 = (*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40)) * local_48;
          local_4c = (*(float *)(param_1 + 8) - *(float *)(param_1 + 0x42)) * local_48;
          local_48 = (*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44)) * local_48;
          *(float *)(param_1 + 0x12) = local_50 + *(float *)(param_1 + 0x12);
          *(float *)(param_1 + 0x14) = local_4c + *(float *)(param_1 + 0x14);
          *(float *)(param_1 + 0x16) = local_48 + *(float *)(param_1 + 0x16);
          fVar1 = FLOAT_803e4138;
          *(float *)(param_1 + 0x12) = FLOAT_803e4138 * *(float *)(param_1 + 0x12);
          *(float *)(param_1 + 0x14) = fVar1 * *(float *)(param_1 + 0x14);
          *(float *)(param_1 + 0x16) = fVar1 * *(float *)(param_1 + 0x16);
        }
      }
      break;
    case 7:
      if (*(char *)(iVar8 + 0xa98) == '\x02') {
        *(undefined *)(iVar8 + 0xa98) = 1;
      }
      *(byte *)(iVar8 + 0xa9b) = *(byte *)(iVar8 + 0xa9b) | 2;
      iVar7 = FUN_8019af64((double)FLOAT_803e4138,param_1,iVar8 + 0x6bc,1,iVar8 + 0x7fc);
      if (iVar7 != 0) {
        *(undefined *)(iVar8 + 0xa80) = 8;
        FUN_8002f574(param_1,0x32);
      }
      break;
    case 8:
      iVar7 = FUN_80036e58(3,param_1,&local_54);
      if ((iVar7 != 0) && (local_54 < FLOAT_803e4158)) {
        FUN_8011508c(iVar8);
        *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 0x10;
      }
      if ((local_54 <= FLOAT_803e4158) ||
         (dVar9 = (double)FUN_80021690(iVar3 + 0x18,param_1 + 0xc), (double)FLOAT_803e413c <= dVar9)
         ) {
        if (((*(byte *)(iVar8 + 0xa9b) & 4) == 0) &&
           (*(int *)(&DAT_80322954 + (uint)*(byte *)(iVar8 + 0xa80) * 4) != 0xe)) {
          *(undefined *)(iVar8 + 0xa98) = 2;
          *(byte *)(iVar8 + 0xa9b) = *(byte *)(iVar8 + 0xa9b) | 5;
          FUN_80114184(0xe,iVar8 + 0xa68);
          *(undefined4 *)(&DAT_80322954 + (uint)*(byte *)(iVar8 + 0xa80) * 4) = 0xe;
        }
      }
      else {
        *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xef;
        if (((*(byte *)(iVar8 + 0xa9b) & 4) == 0) &&
           (*(int *)(&DAT_80322954 + (uint)*(byte *)(iVar8 + 0xa80) * 4) != 0)) {
          FUN_80114084(0xf,iVar8 + 0xa68);
          *(byte *)(iVar8 + 0xa9b) = *(byte *)(iVar8 + 0xa9b) | 5;
          *(undefined4 *)(&DAT_80322954 + (uint)*(byte *)(iVar8 + 0xa80) * 4) = 0;
        }
        if (*(char *)(iVar8 + 0xa98) == '\x02') {
          *(undefined *)(iVar8 + 0xa98) = 1;
          iVar7 = *(char *)(iVar8 + 0xa99) + 1;
          cVar2 = (char)(iVar7 >> 0x1f);
          *(byte *)(iVar8 + 0xa99) = ((byte)iVar7 & 1 ^ -cVar2) + cVar2;
        }
      }
      if (((*(byte *)(iVar8 + 0xa9b) & 4) != 0) &&
         (iVar7 = FUN_8019b1d8((double)FLOAT_803e4128,param_1,iVar8 + 0xa68,iVar8 + 0x7fc),
         iVar7 != 0)) {
        FUN_80030334((double)FLOAT_803e4110,param_1,0x1a,0);
        *(byte *)(iVar8 + 0xa9b) = *(byte *)(iVar8 + 0xa9b) & 0xfa;
      }
      iVar7 = FUN_8001ffb4(0x43);
      if (iVar7 != 0) {
        *(undefined *)(iVar8 + 0xa80) = 9;
        *(undefined *)(iVar8 + 0xa99) = 0;
      }
      break;
    case 9:
      iVar7 = FUN_80036e58(3,param_1,&local_54);
      if ((iVar7 != 0) && (local_54 < FLOAT_803e4158)) {
        FUN_8011508c(iVar8);
      }
      if ((local_54 <= FLOAT_803e4158) ||
         (dVar9 = (double)FUN_80021690(iVar3 + 0x18,param_1 + 0xc), (double)FLOAT_803e413c <= dVar9)
         ) {
        if (((*(byte *)(iVar8 + 0xa9b) & 4) == 0) &&
           (*(int *)(&DAT_80322954 + (uint)*(byte *)(iVar8 + 0xa80) * 4) != 0xe)) {
          *(undefined *)(iVar8 + 0xa98) = 2;
          *(byte *)(iVar8 + 0xa9b) = *(byte *)(iVar8 + 0xa9b) | 5;
          FUN_80114184(0xe,iVar8 + 0xa68);
          *(undefined4 *)(&DAT_80322954 + (uint)*(byte *)(iVar8 + 0xa80) * 4) = 0xe;
        }
      }
      else {
        if (((*(byte *)(iVar8 + 0xa9b) & 4) == 0) &&
           (*(int *)(&DAT_80322954 + (uint)*(byte *)(iVar8 + 0xa80) * 4) != 0)) {
          FUN_80114084(0xf,iVar8 + 0xa68);
          *(byte *)(iVar8 + 0xa9b) = *(byte *)(iVar8 + 0xa9b) | 5;
          *(undefined4 *)(&DAT_80322954 + (uint)*(byte *)(iVar8 + 0xa80) * 4) = 0;
        }
        if (*(char *)(iVar8 + 0xa98) == '\x02') {
          *(undefined *)(iVar8 + 0xa98) = 1;
          iVar7 = *(char *)(iVar8 + 0xa99) + 1;
          cVar2 = (char)(iVar7 >> 0x1f);
          *(byte *)(iVar8 + 0xa99) = ((byte)iVar7 & 1 ^ -cVar2) + cVar2;
        }
      }
      if (((*(byte *)(iVar8 + 0xa9b) & 4) != 0) &&
         (iVar7 = FUN_8019b1d8((double)FLOAT_803e4128,param_1,iVar8 + 0xa68,iVar8 + 0x7fc),
         iVar7 != 0)) {
        FUN_80030334((double)FLOAT_803e4110,param_1,0x1a,0);
        *(byte *)(iVar8 + 0xa9b) = *(byte *)(iVar8 + 0xa9b) & 0xfa;
      }
      iVar7 = FUN_8001ffb4(0x4be);
      if (iVar7 != 0) {
        *(undefined *)(iVar8 + 0xa80) = 10;
        FUN_80030334((double)FLOAT_803e4110,param_1,0x1a,0);
        *(undefined4 *)(param_1 + 0x7a) = 0;
      }
      break;
    case 10:
      if (*(char *)(iVar8 + 0xa98) == '\x02') {
        *(undefined *)(iVar8 + 0xa98) = 1;
      }
      *(byte *)(iVar8 + 0xa9b) = *(byte *)(iVar8 + 0xa9b) | 2;
      iVar7 = FUN_8019af64((double)FLOAT_803e415c,param_1,iVar8 + 0x6bc,2,iVar8 + 0x7fc);
      if (iVar7 != 0) {
        *(undefined *)(iVar8 + 0xa80) = 0xb;
      }
      break;
    case 0xb:
      if (*(char *)(iVar8 + 0xa98) == '\x02') {
        *(undefined *)(iVar8 + 0xa98) = 1;
      }
      *(undefined *)(param_1 + 0x1b) = 0;
      *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
      FUN_8002ce88(param_1);
      param_1[3] = param_1[3] | 0x4000;
      *(undefined *)(iVar8 + 0xa80) = 0xf;
      break;
    case 0xc:
      if (*(char *)(iVar8 + 0xa98) == '\x02') {
        *(undefined *)(iVar8 + 0xa98) = 1;
      }
      iVar7 = FUN_8001ffb4(0x4b7);
      if (iVar7 != 0) {
        (**(code **)(*DAT_803dca50 + 0x48))(param_1);
        (**(code **)(*DAT_803dca54 + 0x48))(0xb,param_1,0xffffffff);
        FUN_800200e8(0x4b7,0);
      }
      iVar7 = FUN_8001ffb4(0x49a);
      if (iVar7 != 0) {
        *(undefined *)(iVar8 + 0xa80) = 0xd;
      }
      break;
    case 0xd:
      if (*(char *)(iVar8 + 0xa98) == '\x02') {
        *(undefined *)(iVar8 + 0xa98) = 1;
      }
      iVar7 = FUN_8001ffb4(0x4b7);
      if (iVar7 != 0) {
        (**(code **)(*DAT_803dca50 + 0x48))(param_1);
        (**(code **)(*DAT_803dca54 + 0x48))(10,param_1,0xffffffff);
        FUN_800200e8(0x4b7,0);
      }
      iVar7 = FUN_8001ffb4(0x4aa);
      if (iVar7 != 0) {
        *(undefined *)(iVar8 + 0xa80) = 0xe;
      }
      break;
    case 0xe:
      if (*(char *)(iVar8 + 0xa98) == '\x02') {
        *(undefined *)(iVar8 + 0xa98) = 1;
      }
      break;
    case 0xf:
      param_1[3] = param_1[3] | 0x4000;
      FUN_8002ce88(param_1);
      *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
           *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
    }
    FUN_80115094(param_1,iVar8);
    iVar7 = FUN_80038024(param_1);
    if (iVar7 != 0) {
      FUN_80014b3c(0,0x100);
      iVar7 = (**(code **)(*DAT_803dca68 + 0x20))(0x2e8);
      if (iVar7 == 0) {
        if (*(char *)(iVar8 + 0xa98) == '\x01') {
          piVar5 = (int *)FUN_8007fff8(&DAT_8032284c,0xf,*(undefined *)(iVar8 + 0xa80));
          iVar3 = FUN_80296a14(iVar3);
          if (iVar3 < 4) {
            iVar3 = piVar5[1];
          }
          else {
            iVar3 = *piVar5;
          }
          uVar6 = (uint)(int)*(char *)(iVar8 + 0xa9a) >> 0x1f;
          if ((((int)*(char *)(iVar8 + 0xa9a) & 1U ^ uVar6) != uVar6) && (piVar5[2] != -1)) {
            iVar3 = piVar5[2];
          }
          *(char *)(iVar8 + 0xa9a) = *(char *)(iVar8 + 0xa9a) + '\x01';
          if (iVar3 != -1) {
            *(undefined *)(iVar8 + 0xa98) = 2;
            (**(code **)(*DAT_803dca54 + 0x48))(iVar3,param_1,0xffffffff);
          }
        }
      }
      else {
        FUN_800200e8(0x4ab,1);
      }
    }
    iVar3 = FUN_8001ffb4(0x902);
    if ((iVar3 != 0) &&
       (piVar5 = (int *)FUN_8007fff8(&DAT_8032284c,0xf,*(undefined *)(iVar8 + 0xa80)), *piVar5 != -1
       )) {
      *(undefined *)(iVar8 + 0xa98) = 2;
      (**(code **)(*DAT_803dca54 + 0x48))(*piVar5,param_1,0xffffffff);
      FUN_800200e8(0x902,0);
    }
    iVar3 = *(int *)(&DAT_80322954 + (uint)*(byte *)(iVar8 + 0xa80) * 4);
    if (((iVar3 != -1) && ((*(byte *)(iVar8 + 0xa9b) & 1) == 0)) && (param_1[0x50] != iVar3)) {
      FUN_80030334((double)FLOAT_803e4110,param_1,iVar3,0);
      FUN_8002f574(param_1,0x50);
    }
    local_20 = (double)CONCAT44(0x43300000,(uint)DAT_803db410);
    iVar3 = FUN_8002fa48((double)*(float *)(iVar8 + 0x7fc),
                         (double)(float)(local_20 - DOUBLE_803e4160),param_1,auStack68);
    if (((iVar3 != 0) && ((*(byte *)(iVar8 + 0xa9b) & 1) != 0)) &&
       ((param_1[0x50] != 0x1a && (param_1[0x50] != 9)))) {
      *(byte *)(iVar8 + 0xa9b) = *(byte *)(iVar8 + 0xa9b) & 0xfe;
    }
    FUN_8019ae3c(param_1,auStack68,&DAT_803dbe20);
    iVar3 = FUN_80080100(0x3c);
    if (iVar3 != 0) {
      FUN_800393f8(param_1,iVar8 + 0x624,0xdf,0x1000,0xffffffff,0);
    }
    FUN_80038f38(param_1,iVar8 + 0x624);
    FUN_8003b310(param_1,iVar8 + 0x654);
    uVar6 = FUN_8001ffb4(0x4b);
    if (*(byte *)(iVar8 + 0xa80) != uVar6) {
      FUN_800200e8(0x4b);
    }
  }
  return 0;
}

