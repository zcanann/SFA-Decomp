// Function: FUN_80134428
// Entry: 80134428
// Size: 708 bytes

undefined4 FUN_80134428(void)

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
  undefined8 local_10;
  
  dVar4 = DOUBLE_803e2f50;
  if (DAT_803de5f0 < 10) {
    fVar1 = FLOAT_803de5e8 + FLOAT_803dc074;
    if ((float)((double)CONCAT44(0x43300000,
                                 (uint)*(ushort *)(&DAT_8031d302 + (uint)DAT_803de5f0 * 0x98)) -
               DOUBLE_803e2f50) <= fVar1) {
      DAT_803de5f0 = DAT_803de5f0 + 1;
    }
    FLOAT_803de5e8 = fVar1;
    if (DAT_803de5f0 < 10) {
      iVar9 = 0;
      iVar8 = (uint)DAT_803de5f0 * 0x98;
      for (iVar7 = 0; iVar7 < (int)(uint)(byte)(&DAT_8031d304)[iVar8]; iVar7 = iVar7 + 1) {
        puVar10 = (ushort *)(&DAT_8031d270 + iVar9 + iVar8);
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
                               DOUBLE_803e2f58);
                fVar3 = FLOAT_803e2f38;
                if ((FLOAT_803e2f38 <= fVar2) && (fVar3 = fVar2, FLOAT_803e2f3c < fVar2)) {
                  fVar3 = FLOAT_803e2f3c;
                }
                cVar6 = -1 - (char)(int)(FLOAT_803e2f40 * fVar3);
              }
            }
            else {
              cVar6 = -1;
            }
          }
          else {
            local_10 = (double)CONCAT44(0x43300000,puVar10[1] - uVar5 ^ 0x80000000);
            fVar2 = (fVar1 - (float)((double)CONCAT44(0x43300000,uVar5) - dVar4)) /
                    (float)(local_10 - DOUBLE_803e2f58);
            fVar3 = FLOAT_803e2f38;
            if ((FLOAT_803e2f38 <= fVar2) && (fVar3 = fVar2, FLOAT_803e2f3c < fVar2)) {
              fVar3 = FLOAT_803e2f3c;
            }
            cVar6 = (char)(int)(FLOAT_803e2f40 * fVar3);
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
                                        (uint)*(ushort *)(&DAT_8031d300 + (uint)DAT_803de5f0 * 0x98)
                                       ), (float)(local_10 - dVar4) <= fVar1)) {
          *(float *)(puVar10 + 6) =
               FLOAT_803e2f44 * (FLOAT_803dc074 / FLOAT_803e2f48) + *(float *)(puVar10 + 6);
        }
        iVar9 = iVar9 + 0x10;
      }
    }
  }
  return 0;
}

