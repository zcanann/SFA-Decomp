// Function: FUN_8001d22c
// Entry: 8001d22c
// Size: 1208 bytes

void FUN_8001d22c(int param_1)

{
  float fVar1;
  double dVar2;
  double dVar3;
  int iVar4;
  uint uVar5;
  
  iVar4 = *(int *)(param_1 + 0x2d8);
  if (iVar4 == 2) {
    *(float *)(param_1 + 0x2e0) =
         *(float *)(param_1 + 0x2dc) * FLOAT_803dc074 + *(float *)(param_1 + 0x2e0);
  }
  else if (((iVar4 < 2) && (0 < iVar4)) &&
          (*(float *)(param_1 + 0x2e4) =
                *(float *)(param_1 + 0x2dc) * FLOAT_803dc074 + *(float *)(param_1 + 0x2e4),
          FLOAT_803df3e0 <= *(float *)(param_1 + 0x2e4))) {
    uVar5 = FUN_80022264(0,100);
    *(float *)(param_1 + 0x2e0) =
         (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803df400) / FLOAT_803df3f8
    ;
    *(float *)(param_1 + 0x2e4) = FLOAT_803df3dc;
  }
  fVar1 = *(float *)(param_1 + 0x2e0);
  if (fVar1 <= FLOAT_803df3e0) {
    if (fVar1 < FLOAT_803df3dc) {
      *(float *)(param_1 + 0x2e0) = -fVar1;
      *(float *)(param_1 + 0x2dc) = -*(float *)(param_1 + 0x2dc);
    }
  }
  else {
    *(float *)(param_1 + 0x2e0) = FLOAT_803df3e0 - (fVar1 - FLOAT_803df3e0);
    *(float *)(param_1 + 0x2dc) = -*(float *)(param_1 + 0x2dc);
  }
  dVar3 = DOUBLE_803df400;
  dVar2 = DOUBLE_803df3f0;
  *(char *)(param_1 + 0xa8) =
       (char)(int)(*(float *)(param_1 + 0x2e0) *
                   (float)((double)CONCAT44(0x43300000,
                                            (uint)*(byte *)(param_1 + 0xb0) -
                                            (uint)*(byte *)(param_1 + 0xac) ^ 0x80000000) -
                          DOUBLE_803df400) +
                  (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xac)) -
                         DOUBLE_803df3f0));
  *(char *)(param_1 + 0xa9) =
       (char)(int)(*(float *)(param_1 + 0x2e0) *
                   (float)((double)CONCAT44(0x43300000,
                                            (uint)*(byte *)(param_1 + 0xb1) -
                                            (uint)*(byte *)(param_1 + 0xad) ^ 0x80000000) - dVar3) +
                  (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xad)) - dVar2));
  *(char *)(param_1 + 0xaa) =
       (char)(int)(*(float *)(param_1 + 0x2e0) *
                   (float)((double)CONCAT44(0x43300000,
                                            (uint)*(byte *)(param_1 + 0xb2) -
                                            (uint)*(byte *)(param_1 + 0xae) ^ 0x80000000) - dVar3) +
                  (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xae)) - dVar2));
  *(char *)(param_1 + 0xab) =
       (char)(int)(*(float *)(param_1 + 0x2e0) *
                   (float)((double)CONCAT44(0x43300000,
                                            (uint)*(byte *)(param_1 + 0xb3) -
                                            (uint)*(byte *)(param_1 + 0xaf) ^ 0x80000000) - dVar3) +
                  (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xaf)) - dVar2));
  *(char *)(param_1 + 0xa8) =
       (char)(int)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xa8)) - dVar2) *
                  *(float *)(param_1 + 0x138));
  *(char *)(param_1 + 0xa9) =
       (char)(int)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xa9)) - dVar2) *
                  *(float *)(param_1 + 0x138));
  *(char *)(param_1 + 0xaa) =
       (char)(int)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xaa)) - dVar2) *
                  *(float *)(param_1 + 0x138));
  *(char *)(param_1 + 0xab) =
       (char)(int)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0xab)) - dVar2) *
                  *(float *)(param_1 + 0x138));
  *(char *)(param_1 + 0x100) =
       (char)(int)(*(float *)(param_1 + 0x2e0) *
                   (float)((double)CONCAT44(0x43300000,
                                            (uint)*(byte *)(param_1 + 0x108) -
                                            (uint)*(byte *)(param_1 + 0x104) ^ 0x80000000) - dVar3)
                  + (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x104)) - dVar2));
  *(char *)(param_1 + 0x101) =
       (char)(int)(*(float *)(param_1 + 0x2e0) *
                   (float)((double)CONCAT44(0x43300000,
                                            (uint)*(byte *)(param_1 + 0x109) -
                                            (uint)*(byte *)(param_1 + 0x105) ^ 0x80000000) - dVar3)
                  + (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x105)) - dVar2));
  *(char *)(param_1 + 0x102) =
       (char)(int)(*(float *)(param_1 + 0x2e0) *
                   (float)((double)CONCAT44(0x43300000,
                                            (uint)*(byte *)(param_1 + 0x10a) -
                                            (uint)*(byte *)(param_1 + 0x106) ^ 0x80000000) - dVar3)
                  + (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x106)) - dVar2));
  *(char *)(param_1 + 0x103) =
       (char)(int)(*(float *)(param_1 + 0x2e0) *
                   (float)((double)CONCAT44(0x43300000,
                                            (uint)*(byte *)(param_1 + 0x10b) -
                                            (uint)*(byte *)(param_1 + 0x107) ^ 0x80000000) - dVar3)
                  + (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x107)) - dVar2));
  *(char *)(param_1 + 0x100) =
       (char)(int)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x100)) - dVar2) *
                  *(float *)(param_1 + 0x138));
  *(char *)(param_1 + 0x101) =
       (char)(int)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x101)) - dVar2) *
                  *(float *)(param_1 + 0x138));
  *(char *)(param_1 + 0x102) =
       (char)(int)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x102)) - dVar2) *
                  *(float *)(param_1 + 0x138));
  *(char *)(param_1 + 0x103) =
       (char)(int)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x103)) - dVar2) *
                  *(float *)(param_1 + 0x138));
  return;
}

