// Function: FUN_80275e48
// Entry: 80275e48
// Size: 600 bytes

void FUN_80275e48(int param_1,uint *param_2)

{
  int iVar1;
  ushort *puVar2;
  uint uVar3;
  uint uVar4;
  int local_38;
  int local_34;
  undefined2 local_30;
  ushort local_2e;
  double local_20;
  undefined4 local_18;
  uint uStack20;
  double local_10;
  
  puVar2 = (ushort *)FUN_80275058(*param_2 >> 8 & 0xffff);
  if (puVar2 != (ushort *)0x0) {
    if (*param_2 >> 0x18 == 0) {
      local_38 = CONCAT22(*puVar2 << 8 | (ushort)((uint)*puVar2 >> 8),
                          puVar2[1] << 8 | (ushort)((uint)puVar2[1] >> 8));
      local_34 = CONCAT22(puVar2[2] << 8 | (ushort)((uint)puVar2[2] >> 8),
                          puVar2[3] << 8 | (ushort)((uint)puVar2[3] >> 8));
      FUN_8028348c(*(uint *)(param_1 + 0xf4) & 0xff,&local_38,0);
    }
    else {
      local_38 = CONCAT13(*(undefined *)((int)puVar2 + 3),
                          CONCAT12(*(undefined *)(puVar2 + 1),
                                   CONCAT11(*(undefined *)((int)puVar2 + 1),*(undefined *)puVar2)));
      local_34 = CONCAT13(*(undefined *)((int)puVar2 + 7),
                          CONCAT12(*(undefined *)(puVar2 + 3),
                                   CONCAT11(*(undefined *)((int)puVar2 + 5),
                                            *(undefined *)(puVar2 + 2))));
      local_10 = (double)(longlong)
                         (int)(FLOAT_803e77f0 *
                              *(float *)(&DAT_8032fb9c +
                                        (((uint)puVar2[4] << 8 | (int)(uint)puVar2[4] >> 8) >> 3 &
                                        0x1ffc)));
      local_30 = (undefined2)
                 (int)(FLOAT_803e77f0 *
                      *(float *)(&DAT_8032fb9c +
                                (((uint)puVar2[4] << 8 | (int)(uint)puVar2[4] >> 8) >> 3 & 0x1ffc)))
      ;
      local_2e = puVar2[5] << 8 | (ushort)((uint)puVar2[5] >> 8);
      uVar4 = CONCAT13(*(undefined *)((int)puVar2 + 0xf),
                       CONCAT12(*(undefined *)(puVar2 + 7),
                                CONCAT11(*(undefined *)((int)puVar2 + 0xd),
                                         *(undefined *)(puVar2 + 6))));
      uVar3 = CONCAT13(*(undefined *)((int)puVar2 + 0x13),
                       CONCAT12(*(undefined *)(puVar2 + 9),
                                CONCAT11(*(undefined *)((int)puVar2 + 0x11),
                                         *(undefined *)(puVar2 + 8))));
      if (uVar4 != 0x80000000) {
        uStack20 = uVar4 ^ 0x80000000;
        local_10 = (double)CONCAT44(0x43300000,*(undefined4 *)(param_1 + 0x158));
        local_18 = 0x43300000;
        iVar1 = (int)(FLOAT_803e77f4 * (float)(local_10 - DOUBLE_803e7800) *
                     (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e7808));
        local_20 = (double)(longlong)iVar1;
        local_38 = local_38 + iVar1;
      }
      if (uVar3 != 0x80000000) {
        uStack20 = uVar3 ^ 0x80000000;
        local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x12f));
        local_18 = 0x43300000;
        iVar1 = (int)(FLOAT_803e77f8 * (float)(local_20 - DOUBLE_803e7800) *
                     (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e7808));
        local_10 = (double)(longlong)iVar1;
        local_34 = local_34 + iVar1;
      }
      FUN_8028348c(*(uint *)(param_1 + 0xf4) & 0xff,&local_38,1);
    }
    *(uint *)(param_1 + 0x118) = *(uint *)(param_1 + 0x118) | 0x100;
  }
  return;
}

