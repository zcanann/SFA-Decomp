// Function: FUN_801340a0
// Entry: 801340a0
// Size: 708 bytes

undefined4 FUN_801340a0(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  uint uVar5;
  char cVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  ushort *puVar10;
  double local_10;
  
  dVar4 = DOUBLE_803e22c0;
  if (DAT_803dd970 < 10) {
    fVar1 = FLOAT_803dd968 + FLOAT_803db414;
    if ((float)((double)CONCAT44(0x43300000,
                                 (uint)*(ushort *)(&DAT_8031c6b2 + (uint)DAT_803dd970 * 0x98)) -
               DOUBLE_803e22c0) <= fVar1) {
      DAT_803dd970 = DAT_803dd970 + 1;
    }
    FLOAT_803dd968 = fVar1;
    if (DAT_803dd970 < 10) {
      iVar9 = 0;
      iVar8 = (uint)DAT_803dd970 * 0x98;
      for (iVar7 = 0; iVar7 < (int)(uint)(byte)(&DAT_8031c6b4)[iVar8]; iVar7 = iVar7 + 1) {
        puVar10 = (ushort *)(&DAT_8031c620 + iVar9 + iVar8);
        uVar5 = (uint)*puVar10;
        if ((float)((double)CONCAT44(0x43300000,uVar5) - dVar4) <= fVar1) {
          if ((float)((double)CONCAT44(0x43300000,(uint)puVar10[1]) - dVar4) <= fVar1) {
            uVar5 = (uint)puVar10[2];
            local_10 = (double)CONCAT44(0x43300000,uVar5);
            if ((float)(local_10 - dVar4) <= fVar1) {
              local_10 = (double)CONCAT44(0x43300000,(uint)puVar10[3]);
              if ((float)(local_10 - dVar4) <= fVar1) {
                cVar6 = '\0';
              }
              else {
                local_10 = (double)CONCAT44(0x43300000,uVar5);
                fVar2 = (fVar1 - (float)(local_10 - dVar4)) /
                        (float)((double)CONCAT44(0x43300000,puVar10[3] - uVar5 ^ 0x80000000) -
                               DOUBLE_803e22c8);
                fVar3 = FLOAT_803e22a8;
                if ((FLOAT_803e22a8 <= fVar2) && (fVar3 = fVar2, FLOAT_803e22ac < fVar2)) {
                  fVar3 = FLOAT_803e22ac;
                }
                cVar6 = -1 - (char)(int)(FLOAT_803e22b0 * fVar3);
              }
            }
            else {
              cVar6 = -1;
            }
          }
          else {
            local_10 = (double)CONCAT44(0x43300000,puVar10[1] - uVar5 ^ 0x80000000);
            fVar2 = (fVar1 - (float)((double)CONCAT44(0x43300000,uVar5) - dVar4)) /
                    (float)(local_10 - DOUBLE_803e22c8);
            fVar3 = FLOAT_803e22a8;
            if ((FLOAT_803e22a8 <= fVar2) && (fVar3 = fVar2, FLOAT_803e22ac < fVar2)) {
              fVar3 = FLOAT_803e22ac;
            }
            cVar6 = (char)(int)(FLOAT_803e22b0 * fVar3);
          }
        }
        else {
          cVar6 = '\0';
        }
        *(char *)((int)puVar10 + 0xb) = cVar6;
        local_10 = (double)CONCAT44(0x43300000,(uint)*puVar10);
        if ((((float)(local_10 - dVar4) <= fVar1) &&
            (local_10 = (double)CONCAT44(0x43300000,(uint)puVar10[3]),
            fVar1 <= (float)(local_10 - dVar4))) &&
           (local_10 = (double)CONCAT44(0x43300000,
                                        (uint)*(ushort *)(&DAT_8031c6b0 + (uint)DAT_803dd970 * 0x98)
                                       ), (float)(local_10 - dVar4) <= fVar1)) {
          *(float *)(puVar10 + 6) =
               FLOAT_803e22b4 * (FLOAT_803db414 / FLOAT_803e22b8) + *(float *)(puVar10 + 6);
        }
        iVar9 = iVar9 + 0x10;
      }
    }
  }
  return 0;
}

