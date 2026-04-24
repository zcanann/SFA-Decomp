// Function: FUN_8008fdac
// Entry: 8008fdac
// Size: 224 bytes

/* WARNING: Removing unreachable block (ram,0x8008fe6c) */
/* WARNING: Removing unreachable block (ram,0x8008fe64) */
/* WARNING: Removing unreachable block (ram,0x8008fdc4) */
/* WARNING: Removing unreachable block (ram,0x8008fdbc) */

void FUN_8008fdac(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 undefined2 param_5,undefined param_6,undefined param_7)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  double extraout_f1;
  double dVar4;
  undefined8 uVar5;
  
  uVar5 = FUN_80286840();
  puVar1 = (undefined4 *)((ulonglong)uVar5 >> 0x20);
  puVar3 = (undefined4 *)uVar5;
  dVar4 = extraout_f1;
  puVar2 = (undefined4 *)FUN_80023d8c(0x28,0x17);
  if (puVar2 != (undefined4 *)0x0) {
    *puVar2 = *puVar1;
    puVar2[1] = puVar1[1];
    puVar2[2] = puVar1[2];
    puVar2[3] = *puVar3;
    puVar2[4] = puVar3[1];
    puVar2[5] = puVar3[2];
    puVar2[6] = (float)dVar4;
    puVar2[7] = (float)param_2;
    *(undefined2 *)((int)puVar2 + 0x22) = param_5;
    *(undefined *)((int)puVar2 + 0x26) = param_6;
    *(undefined2 *)(puVar2 + 8) = 0;
    *(undefined2 *)(puVar2 + 9) = 0xffff;
    *(undefined *)((int)puVar2 + 0x27) = param_7;
  }
  FUN_8028688c();
  return;
}

