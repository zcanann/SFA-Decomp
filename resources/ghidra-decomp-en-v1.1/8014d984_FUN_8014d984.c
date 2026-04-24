// Function: FUN_8014d984
// Entry: 8014d984
// Size: 1236 bytes

void FUN_8014d984(undefined8 param_1,undefined8 param_2,double param_3,double param_4,double param_5
                 ,double param_6,double param_7,undefined8 param_8)

{
  float fVar1;
  ushort *puVar2;
  int iVar3;
  int iVar4;
  byte bVar6;
  uint uVar5;
  undefined4 uVar7;
  undefined4 in_r6;
  int in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar8;
  int *piVar9;
  double dVar10;
  undefined8 uVar11;
  double dVar12;
  
  puVar2 = (ushort *)FUN_80286840();
  piVar9 = *(int **)(puVar2 + 0x5c);
  iVar8 = *(int *)(puVar2 + 0x26);
  iVar3 = FUN_8002ba84();
  iVar4 = FUN_8001496c();
  if (iVar4 != 4) {
    if ((piVar9[0xb9] & 0x8000006U) == 0) {
      dVar10 = (double)*(float *)(puVar2 + 6);
      dVar12 = (double)*(float *)(puVar2 + 10);
      iVar4 = FUN_8005b2e8();
      if (iVar4 == 0) goto LAB_8014de60;
    }
    else {
      dVar10 = (double)*(float *)(puVar2 + 6);
      dVar12 = (double)*(float *)(puVar2 + 8);
      param_3 = (double)*(float *)(puVar2 + 10);
      iVar4 = FUN_8005b478(dVar10,dVar12);
      if (iVar4 == -1) goto LAB_8014de60;
    }
    bVar6 = FUN_8002b11c((int)puVar2);
    if (bVar6 == 0) {
      if (piVar9[0xa7] == 0) {
        iVar4 = FUN_8002bac4();
        piVar9[0xa7] = iVar4;
      }
      else if ((*(ushort *)(piVar9[0xa7] + 0xb0) & 0x40) != 0) {
        iVar4 = FUN_8002bac4();
        piVar9[0xa7] = iVar4;
      }
      piVar9[0xb8] = piVar9[0xb7];
      uVar11 = FUN_8014a4b8(dVar10,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,
                            (int)puVar2,(int)piVar9);
      if (((piVar9[0xb7] & 1U) == 0) || ((piVar9[0xb7] & 2U) != 0)) {
        if (*(int *)(puVar2 + 0x7a) != 0) {
          if ((int)*(short *)(iVar8 + 0x1a) == 0xffffffff) {
            if ((int)*(short *)(iVar8 + 0x18) == 0xffffffff) {
              if (((((*(int *)(iVar8 + 0x14) == -1) || (*(short *)(iVar8 + 0x2c) == 0)) ||
                   (iVar4 = (**(code **)(*DAT_803dd72c + 0x68))(), iVar4 == 0)) ||
                  (((piVar9[0xb7] & 0x800U) != 0 || (iVar4 = FUN_8002bac4(), iVar4 == 0)))) ||
                 (dVar10 = FUN_80021794((float *)(iVar4 + 0x18),(float *)(iVar8 + 8)),
                 dVar10 <= (double)FLOAT_803e3298)) goto LAB_8014de60;
              uVar11 = FUN_8014de78(dVar10,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,
                                    puVar2,iVar8,0);
              piVar9[0xb7] = piVar9[0xb7] | 0x1000;
              piVar9[0xb8] = piVar9[0xb8] & 0xffffefff;
            }
            else {
              uVar5 = FUN_80020078((int)*(short *)(iVar8 + 0x18));
              if (((uVar5 != 0) || ((piVar9[0xb7] & 0x800U) != 0)) ||
                 ((iVar4 = FUN_8002bac4(), iVar4 == 0 ||
                  (dVar10 = FUN_80021794((float *)(iVar4 + 0x18),(float *)(iVar8 + 8)),
                  dVar10 <= (double)FLOAT_803e3298)))) goto LAB_8014de60;
              uVar11 = FUN_8014de78(dVar10,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,
                                    puVar2,iVar8,0);
              piVar9[0xb7] = piVar9[0xb7] | 0x1000;
              piVar9[0xb8] = piVar9[0xb8] & 0xffffefff;
            }
          }
          else {
            uVar5 = FUN_80020078((int)*(short *)(iVar8 + 0x1a));
            if (((uVar5 == 0) || ((piVar9[0xb7] & 0x800U) != 0)) || ((piVar9[0xb7] & 0x1000U) == 0))
            goto LAB_8014de60;
            iVar4 = FUN_8002bac4();
            if ((((int)*(short *)(iVar8 + 0x18) != 0xffffffff) &&
                (uVar5 = FUN_80020078((int)*(short *)(iVar8 + 0x18)), uVar5 != 0)) ||
               ((iVar4 == 0 ||
                (dVar10 = FUN_80021794((float *)(iVar4 + 0x18),(float *)(iVar8 + 8)),
                dVar10 <= (double)FLOAT_803e3298)))) goto LAB_8014de60;
            uVar11 = FUN_8014de78(dVar10,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,
                                  puVar2,iVar8,0);
            piVar9[0xb7] = piVar9[0xb7] | 0x1000;
            piVar9[0xb8] = piVar9[0xb8] & 0xffffefff;
          }
        }
        if ((piVar9[0xb7] & 0x8000U) != 0) {
          FUN_8011f670(0);
          uVar11 = (**(code **)(*DAT_803dd728 + 0x20))(puVar2,piVar9 + 1);
          piVar9[0xb7] = piVar9[0xb7] & 0xffff7ffc;
          if ((piVar9[0xb9] & 0x20000U) != 0) {
            iVar4 = *(int *)(puVar2 + 0x26);
            *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar4 + 8);
            *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar4 + 0xc);
            *(undefined4 *)(puVar2 + 10) = *(undefined4 *)(iVar4 + 0x10);
            puVar2[2] = 0;
            puVar2[1] = 0;
            *puVar2 = (ushort)((int)*(char *)(iVar4 + 0x2a) << 8);
            fVar1 = FLOAT_803e31fc;
            *(float *)(puVar2 + 0x12) = FLOAT_803e31fc;
            *(float *)(puVar2 + 0x14) = fVar1;
            *(float *)(puVar2 + 0x16) = fVar1;
          }
        }
        if ((piVar9[0xb9] & 0x80000U) != 0) {
          if ((iVar3 == 0) || (uVar5 = FUN_80020078(0x9e), uVar5 == 0)) {
            *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 0x10;
          }
          else {
            *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) & 0xef;
          }
          if ((iVar3 != 0) && ((*(byte *)((int)puVar2 + 0xaf) & 4) != 0)) {
            in_r6 = 2;
            in_r7 = **(int **)(iVar3 + 0x68);
            uVar11 = (**(code **)(in_r7 + 0x28))(iVar3,puVar2,1);
          }
        }
        uVar7 = 0;
        uVar11 = FUN_80149528(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,
                              piVar9,0);
        if ((piVar9[0xb7] & 0x1800U) == 0) {
          dVar10 = (double)FUN_8014c110(puVar2,(int)piVar9);
          uVar11 = FUN_8014bcf0(dVar10,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,
                                (int)puVar2,(int)piVar9);
        }
        FUN_8014ae50(uVar11,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,piVar9,
                     uVar7,in_r6,in_r7,in_r8,in_r9,in_r10);
      }
      else if (*(char *)(iVar8 + 0x2e) != -1) {
        if ((iVar8 != 0) && ((*(byte *)(iVar8 + 0x2b) & 8) != 0)) {
          *(undefined4 *)(puVar2 + 6) = *(undefined4 *)(iVar8 + 8);
          *(undefined4 *)(puVar2 + 8) = *(undefined4 *)(iVar8 + 0xc);
          *(undefined4 *)(puVar2 + 10) = *(undefined4 *)(iVar8 + 0x10);
        }
        (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar8 + 0x2e),puVar2,0xffffffff);
        piVar9[0xb7] = piVar9[0xb7] | 2;
        piVar9[0xb7] = piVar9[0xb7] & 0xfffffffe;
      }
    }
    else {
      FUN_80149528(dVar10,dVar12,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,piVar9,1);
    }
  }
LAB_8014de60:
  FUN_8028688c();
  return;
}

