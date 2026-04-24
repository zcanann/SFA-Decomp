// Function: FUN_80180b20
// Entry: 80180b20
// Size: 1764 bytes

void FUN_80180b20(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  ushort *puVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  undefined4 *puVar7;
  int iVar8;
  undefined4 in_r7;
  undefined4 in_r8;
  int in_r9;
  undefined4 in_r10;
  int iVar9;
  float *pfVar10;
  double dVar11;
  undefined8 uVar12;
  double dVar13;
  uint local_48;
  undefined4 *local_44;
  ushort local_40 [4];
  float local_38;
  float local_34;
  float local_30;
  float local_2c;
  undefined8 local_28;
  longlong local_20;
  
  puVar2 = (ushort *)FUN_80286840();
  pfVar10 = *(float **)(puVar2 + 0x5c);
  iVar9 = *(int *)(puVar2 + 0x26);
  iVar3 = FUN_8002bac4();
  while (iVar4 = FUN_800375e4((int)puVar2,&local_48,(uint *)0x0,(uint *)0x0), iVar4 != 0) {
    if (local_48 == 0x7000b) {
      FUN_8000bb38((uint)puVar2,0x4e);
      (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
      in_r7 = 0xffffffff;
      in_r8 = 0;
      in_r9 = *DAT_803dd708;
      (**(code **)(in_r9 + 8))(puVar2,0x51a,0,1);
      FUN_800201ac((int)*(short *)(pfVar10 + 3),1);
      iVar4 = (**(code **)(*DAT_803dd72c + 0x8c))();
      uVar5 = *(byte *)(iVar4 + 9) + 1;
      if (*(byte *)(iVar4 + 10) < uVar5) {
        uVar5 = (uint)*(byte *)(iVar4 + 10);
      }
      *(char *)(iVar4 + 9) = (char)uVar5;
      *(undefined *)(pfVar10 + 7) = 1;
    }
  }
  if ((*(char *)((int)pfVar10 + 0x1b) == '\0') || (*(char *)(pfVar10 + 7) == '\x01')) {
    if (*(char *)((int)pfVar10 + 0x1b) == '\0') {
      uVar5 = FUN_80020078((int)*(short *)((int)pfVar10 + 0xe));
      *(char *)((int)pfVar10 + 0x1b) = (char)uVar5;
      *(undefined2 *)(pfVar10 + 2) = 0;
    }
  }
  else {
    dVar13 = (double)*(float *)(puVar2 + 0x14);
    if ((double)FLOAT_803e4550 < dVar13) {
      *(float *)(puVar2 + 0x14) = (float)((double)FLOAT_803e4554 * (double)FLOAT_803dc074 + dVar13);
    }
    *(undefined *)((int)pfVar10 + 0x1a) = 0;
    if (-1 < *(char *)((int)pfVar10 + 0x1e)) {
      dVar13 = (double)*(float *)(puVar2 + 8);
      iVar6 = FUN_80065fcc((double)*(float *)(puVar2 + 6),dVar13,(double)*(float *)(puVar2 + 10),
                           puVar2,&local_44,0,0);
      param_3 = (double)FLOAT_803e4558;
      iVar4 = -1;
      iVar8 = 0;
      puVar7 = local_44;
      if (0 < iVar6) {
        do {
          dVar13 = (double)*(float *)*puVar7;
          dVar11 = (double)(float)(dVar13 - (double)*(float *)(puVar2 + 8));
          if (dVar11 < (double)FLOAT_803e455c) {
            dVar11 = -dVar11;
          }
          if (dVar11 < param_3) {
            iVar4 = iVar8;
            param_3 = dVar11;
          }
          puVar7 = puVar7 + 1;
          iVar8 = iVar8 + 1;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
      }
      if (iVar4 != -1) {
        *(byte *)((int)pfVar10 + 0x1e) = *(byte *)((int)pfVar10 + 0x1e) & 0x7f | 0x80;
        pfVar10[1] = *(float *)local_44[iVar4];
        *(float *)(puVar2 + 0x14) = FLOAT_803e455c;
      }
      if (-1 < *(char *)((int)pfVar10 + 0x1e)) {
        pfVar10[1] = *(float *)(iVar9 + 0xc);
        *(byte *)((int)pfVar10 + 0x1e) = *(byte *)((int)pfVar10 + 0x1e) & 0x7f | 0x80;
      }
    }
    if (*(float *)(puVar2 + 8) < pfVar10[1]) {
      *(float *)(puVar2 + 8) = pfVar10[1];
      *(float *)(puVar2 + 0x14) = FLOAT_803e455c;
    }
    if ((*(short *)(pfVar10 + 2) == 0) && (*(short *)((int)pfVar10 + 10) == 0)) {
      dVar13 = (double)FLOAT_803dc074;
      iVar9 = FUN_8002fb40((double)*pfVar10,dVar13);
      if ((iVar9 == 0) && (*(char *)((int)pfVar10 + 0x1a) == '\0')) {
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 0x12) * FLOAT_803dc074 + *(float *)(puVar2 + 6)
        ;
        dVar13 = (double)*(float *)(puVar2 + 0x16);
        *(float *)(puVar2 + 10) =
             (float)(dVar13 * (double)FLOAT_803dc074 + (double)*(float *)(puVar2 + 10));
      }
      else {
        FUN_8000bb38((uint)puVar2,0x4c);
        (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51f,0,2,0xffffffff,0);
        in_r7 = 0xffffffff;
        in_r8 = 0;
        in_r9 = *DAT_803dd708;
        (**(code **)(in_r9 + 8))(puVar2,0x51f,0,2);
        uVar5 = FUN_80022264(0,4);
        *(char *)(pfVar10 + 6) = (char)uVar5;
        fVar1 = FLOAT_803e455c;
        if (*(char *)((int)pfVar10 + 0x1d) == '\0') {
          *(float *)(puVar2 + 0x12) = FLOAT_803e455c;
          *(float *)(puVar2 + 0x16) = fVar1;
        }
        else {
          *(float *)(puVar2 + 0x12) = FLOAT_803e4560;
          local_34 = FLOAT_803e455c;
          *(float *)(puVar2 + 0x16) = FLOAT_803e455c;
          local_30 = local_34;
          local_2c = local_34;
          local_38 = FLOAT_803e4548;
          local_40[2] = 0;
          local_40[1] = 0;
          local_40[0] = *puVar2;
          FUN_80021b8c(local_40,(float *)(puVar2 + 0x12));
        }
        if (*(char *)((int)pfVar10 + 0x19) != '\0') {
          *(undefined2 *)((int)pfVar10 + 10) = 0xfa;
        }
      }
      iVar9 = FUN_80036974((int)puVar2,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if (iVar9 == 0xe) {
        *(undefined *)((int)pfVar10 + 0x19) = 1;
        FUN_8000bb38((uint)puVar2,0x4d);
      }
    }
    else {
      if (*(short *)(pfVar10 + 2) != 0) {
        local_28 = (double)(longlong)(int)FLOAT_803dc074;
        *(short *)(pfVar10 + 2) = *(short *)(pfVar10 + 2) - (short)(int)FLOAT_803dc074;
        if (*(short *)(pfVar10 + 2) < 1) {
          *(undefined2 *)(pfVar10 + 2) = 0;
        }
      }
      if (*(short *)((int)pfVar10 + 10) != 0) {
        local_28 = (double)(longlong)(int)FLOAT_803dc074;
        *(short *)((int)pfVar10 + 10) = *(short *)((int)pfVar10 + 10) - (short)(int)FLOAT_803dc074;
        if (*(short *)((int)pfVar10 + 10) < 1) {
          *(undefined2 *)((int)pfVar10 + 10) = 0;
          *(undefined *)((int)pfVar10 + 0x19) = 0;
        }
      }
    }
    if (*(char *)(pfVar10 + 6) == '\x04') {
      if (*(char *)((int)pfVar10 + 0x1a) != '\0') {
        *puVar2 = *puVar2 + 0x8001;
        *(undefined *)(pfVar10 + 6) = 0;
      }
      param_3 = (double)FLOAT_803e4564;
      dVar13 = (double)FLOAT_803dc074;
      local_28 = (double)CONCAT44(0x43300000,(int)(short)*puVar2 ^ 0x80000000);
      iVar9 = (int)(param_3 * dVar13 + (double)(float)(local_28 - DOUBLE_803e4570));
      local_20 = (longlong)iVar9;
      *puVar2 = (ushort)iVar9;
    }
    fVar1 = *(float *)(iVar3 + 0x10) - *(float *)(puVar2 + 8);
    if (fVar1 < FLOAT_803e455c) {
      fVar1 = -fVar1;
    }
    if (((fVar1 < FLOAT_803e4568) &&
        (dVar11 = (double)FUN_80021754((float *)(iVar3 + 0x18),(float *)(puVar2 + 0xc)),
        dVar11 < (double)FLOAT_803e456c)) && (uVar5 = FUN_8029698c(iVar3), uVar5 != 0)) {
      uVar5 = FUN_80020078(0xcc0);
      if (uVar5 == 0) {
        *(undefined2 *)(pfVar10 + 4) = 0xffff;
        uVar12 = FUN_80035ff8((int)puVar2);
        FUN_800379bc(uVar12,dVar13,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,0x7000a,
                     (uint)puVar2,(uint)(pfVar10 + 4),in_r7,in_r8,in_r9,in_r10);
        FUN_800201ac(0xcc0,1);
      }
      else {
        iVar3 = (**(code **)(*DAT_803dd72c + 0x8c))();
        if (*(byte *)(iVar3 + 9) < *(byte *)(iVar3 + 10)) {
          FUN_8000bb38((uint)puVar2,0x4e);
          (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
          (**(code **)(*DAT_803dd708 + 8))(puVar2,0x51a,0,1,0xffffffff,0);
          FUN_800201ac((int)*(short *)(pfVar10 + 3),1);
          iVar3 = (**(code **)(*DAT_803dd72c + 0x8c))();
          uVar5 = *(byte *)(iVar3 + 9) + 1;
          if (*(byte *)(iVar3 + 10) < uVar5) {
            uVar5 = (uint)*(byte *)(iVar3 + 10);
          }
          *(char *)(iVar3 + 9) = (char)uVar5;
          *(undefined *)(pfVar10 + 7) = 1;
          *(undefined *)(puVar2 + 0x1b) = 1;
        }
      }
      if (*(int *)(puVar2 + 0x2a) != 0) {
        FUN_80035ff8((int)puVar2);
      }
    }
    *(float *)(puVar2 + 8) = *(float *)(puVar2 + 8) + *(float *)(puVar2 + 0x14);
  }
  FUN_8028688c();
  return;
}

