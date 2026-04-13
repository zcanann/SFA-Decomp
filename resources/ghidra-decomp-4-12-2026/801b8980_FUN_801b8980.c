// Function: FUN_801b8980
// Entry: 801b8980
// Size: 848 bytes

/* WARNING: Type propagation algorithm not settling */

void FUN_801b8980(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  short sVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  undefined uVar8;
  int *piVar6;
  undefined2 *puVar7;
  int *piVar9;
  int iVar10;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined4 *puVar11;
  int iVar12;
  int iVar13;
  undefined8 extraout_f1;
  undefined8 uVar14;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  int local_28 [10];
  
  iVar3 = FUN_8028683c();
  puVar11 = *(undefined4 **)(iVar3 + 0xb8);
  iVar12 = *(int *)(iVar3 + 0x4c);
  uVar14 = extraout_f1;
  uVar4 = FUN_80020078((int)*(short *)(iVar12 + 0x22));
  if (uVar4 != 0) {
    if ((*(byte *)((int)puVar11 + 0x9a7) & 4) == 0) {
      *puVar11 = *(undefined4 *)(iVar3 + 0xc);
      puVar11[1] = *(undefined4 *)(iVar3 + 0x10);
      puVar11[2] = *(undefined4 *)(iVar3 + 0x14);
    }
    else if ((*(byte *)((int)puVar11 + 0x9a7) & 2) == 0) {
      local_28[1] = 0x15;
      param_2 = (double)*(float *)(iVar3 + 0x10);
      param_3 = (double)*(float *)(iVar3 + 0x14);
      iVar5 = (**(code **)(*DAT_803dd71c + 0x14))((double)*(float *)(iVar3 + 0xc),local_28 + 1,1,10)
      ;
      uVar14 = extraout_f1_00;
      if (iVar5 != -1) {
        iVar5 = (**(code **)(*DAT_803dd71c + 0x1c))();
        (**(code **)(*DAT_803dd71c + 0x74))();
        in_r8 = *DAT_803dd71c;
        uVar8 = (**(code **)(in_r8 + 0x78))
                          (iVar5,puVar11 + 3,puVar11 + 0xcb,puVar11 + 0x193,puVar11 + 0x25b);
        *(undefined *)((int)puVar11 + 0x9a6) = uVar8;
        *(byte *)((int)puVar11 + 0x9a7) = *(byte *)((int)puVar11 + 0x9a7) | 2;
        *puVar11 = *(undefined4 *)(iVar5 + 8);
        puVar11[1] = *(undefined4 *)(iVar5 + 0xc);
        puVar11[2] = *(undefined4 *)(iVar5 + 0x10);
        uVar14 = extraout_f1_01;
      }
    }
    sVar2 = *(short *)((int)puVar11 + 0x99e) - (ushort)DAT_803dc070;
    *(short *)((int)puVar11 + 0x99e) = sVar2;
    if (sVar2 < 1) {
      uVar4 = *(byte *)((int)puVar11 + 0x9a7) & 1;
      *(undefined2 *)((int)puVar11 + 0x99e) = *(undefined2 *)(puVar11 + 0x268);
      *(byte *)((int)puVar11 + 0x9a7) = *(byte *)((int)puVar11 + 0x9a7) & 0xfe;
      piVar6 = FUN_80037048(0x2f,local_28);
      iVar10 = 0;
      iVar5 = uVar4 * 2;
      bVar1 = (byte)uVar4;
      piVar9 = piVar6;
      iVar13 = local_28[0];
      if (0 < local_28[0]) {
        do {
          if (*(short *)((int)puVar11 + iVar5 + 0x9a2) == *(short *)(*piVar9 + 0x46)) {
            iVar3 = *(int *)(piVar6[iVar10] + 0x4c);
            *(undefined4 *)(iVar3 + 8) = *puVar11;
            *(undefined4 *)(iVar3 + 0xc) = puVar11[1];
            *(undefined4 *)(iVar3 + 0x10) = puVar11[2];
            *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(iVar12 + 0x14);
            (**(code **)(**(int **)(piVar6[iVar10] + 0x68) + 4))(piVar6[iVar10],iVar3,1);
            FUN_8003709c(piVar6[iVar10],0x2f);
            FUN_80037048(0x2f,local_28);
            iVar3 = 0;
            if (0 < local_28[0]) {
              if ((8 < local_28[0]) && (uVar4 = local_28[0] - 1U >> 3, 0 < local_28[0] + -8)) {
                do {
                  iVar3 = iVar3 + 8;
                  uVar4 = uVar4 - 1;
                } while (uVar4 != 0);
              }
              iVar12 = local_28[0] - iVar3;
              if (iVar3 < local_28[0]) {
                do {
                  iVar12 = iVar12 + -1;
                } while (iVar12 != 0);
              }
            }
            *(byte *)((int)puVar11 + 0x9a7) = *(byte *)((int)puVar11 + 0x9a7) | bVar1 ^ 1;
            goto LAB_801b8cb8;
          }
          piVar9 = piVar9 + 1;
          iVar10 = iVar10 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
      }
      uVar4 = FUN_8002e144();
      if ((uVar4 & 0xff) != 0) {
        puVar7 = FUN_8002becc(0x24,*(undefined2 *)((int)puVar11 + iVar5 + 0x9a2));
        *(undefined4 *)(puVar7 + 4) = *puVar11;
        *(undefined4 *)(puVar7 + 6) = puVar11[1];
        *(undefined4 *)(puVar7 + 8) = puVar11[2];
        *(undefined *)(puVar7 + 2) = *(undefined *)(iVar12 + 4);
        *(undefined *)(puVar7 + 3) = *(undefined *)(iVar12 + 6);
        *(undefined *)((int)puVar7 + 5) = *(undefined *)(iVar12 + 5);
        *(undefined *)((int)puVar7 + 7) = *(undefined *)(iVar12 + 7);
        *(undefined *)((int)puVar7 + 7) = 0xff;
        *(undefined *)((int)puVar7 + 3) = *(undefined *)(iVar12 + 3);
        *(undefined *)(puVar7 + 0xc) = *(undefined *)(iVar12 + 0x1c);
        puVar7[0xd] = (ushort)*(byte *)(iVar12 + 0x1a);
        puVar7[0xe] = (ushort)*(byte *)(iVar12 + 0x1b);
        *(undefined4 *)(puVar7 + 10) = *(undefined4 *)(iVar12 + 0x14);
        FUN_8002e088(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar7,5,
                     *(undefined *)(iVar3 + 0xac),0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
        *(byte *)((int)puVar11 + 0x9a7) = *(byte *)((int)puVar11 + 0x9a7) | bVar1 ^ 1;
      }
    }
  }
LAB_801b8cb8:
  FUN_80286888();
  return;
}

