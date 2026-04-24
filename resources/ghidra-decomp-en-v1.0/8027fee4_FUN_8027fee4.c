// Function: FUN_8027fee4
// Entry: 8027fee4
// Size: 476 bytes

void FUN_8027fee4(void)

{
  char cVar1;
  undefined4 *puVar2;
  double dVar3;
  double dVar4;
  double local_30;
  double local_20;
  
  dVar4 = (double)FLOAT_803e78a0;
  puVar2 = DAT_803de360;
  dVar3 = DOUBLE_803e7888;
  while( true ) {
    if (puVar2 == (undefined4 *)0x0) break;
    if ((puVar2[10] & 0x80000000) == 0) {
      if (*(char *)(puVar2[8] + 0x1c) != -1) {
        if (*(char *)(puVar2[9] + 0x1c) != -1) {
          local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)(puVar2 + 7));
          *(char *)((int)puVar2 + 0x35) =
               (char)(int)((double)(float)(local_20 - dVar3) * (double)(float)puVar2[5]);
          *(undefined *)((int)puVar2 + 0x36) = 0;
          *(char *)(puVar2 + 0xd) = (char)(int)(dVar4 * (double)(float)puVar2[5]);
          if ((puVar2[10] & 1) == 0) {
            *(undefined *)((int)puVar2 + 0x37) = *(undefined *)(puVar2[8] + 0x1c);
            FUN_80272e64(*(undefined *)(puVar2[9] + 0x1c),puVar2 + 0xd);
          }
          else {
            *(undefined *)((int)puVar2 + 0x37) = *(undefined *)(puVar2[9] + 0x1c);
            FUN_80272e64(*(undefined *)(puVar2[8] + 0x1c),puVar2 + 0xd);
          }
          puVar2[10] = puVar2[10] | 0x80000000;
        }
      }
    }
    else {
      cVar1 = *(char *)(puVar2[8] + 0x1c);
      if ((cVar1 == -1) || (*(char *)(puVar2[9] + 0x1c) == -1)) {
        if (((cVar1 != -1) && (cVar1 == *(char *)((int)puVar2 + 0x1d))) ||
           ((*(char *)(puVar2[9] + 0x1c) != -1 &&
            (*(char *)(puVar2[9] + 0x1c) == *(char *)((int)puVar2 + 0x1d))))) {
          FUN_80272e84(*(undefined *)((int)puVar2 + 0x1d),puVar2 + 0xd);
        }
        puVar2[10] = puVar2[10] & 0x7fffffff;
      }
      else {
        local_30 = (double)CONCAT44(0x43300000,(uint)*(byte *)(puVar2 + 7));
        *(char *)((int)puVar2 + 0x35) =
             (char)(int)((double)(float)(local_30 - dVar3) * (double)(float)puVar2[5]);
        *(undefined *)((int)puVar2 + 0x36) = 0;
        *(char *)(puVar2 + 0xd) = (char)(int)(dVar4 * (double)(float)puVar2[5]);
      }
    }
    puVar2 = (undefined4 *)*puVar2;
  }
  return;
}

