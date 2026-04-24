// Function: FUN_801dca2c
// Entry: 801dca2c
// Size: 460 bytes

void FUN_801dca2c(int param_1)

{
  bool bVar1;
  undefined uVar3;
  int iVar2;
  int *piVar4;
  undefined2 *puVar5;
  double dVar6;
  int local_48;
  int local_44;
  undefined auStack64 [32];
  longlong local_20;
  
  puVar5 = *(undefined2 **)(param_1 + 0xb8);
  *(undefined *)((int)puVar5 + 3) = *(undefined *)(puVar5 + 1);
  uVar3 = FUN_8001ffb4(*puVar5);
  *(undefined *)(puVar5 + 1) = uVar3;
  if (*(char *)((int)puVar5 + 3) != *(char *)(puVar5 + 1)) {
    if (*(char *)(puVar5 + 1) == '\0') {
      FUN_8000bb18(param_1,0x3ad);
      *(float *)(puVar5 + 2) = FLOAT_803e55dc;
    }
    else {
      FUN_8000bb18(param_1,0x3ad);
      *(float *)(puVar5 + 2) = FLOAT_803e55d4;
      bVar1 = false;
      iVar2 = FUN_8001ffb4(0x81);
      if ((((iVar2 != 0) && (iVar2 = FUN_8001ffb4(0x82), iVar2 != 0)) &&
          (iVar2 = FUN_8001ffb4(0x83), iVar2 != 0)) && (iVar2 = FUN_8001ffb4(0x84), iVar2 != 0)) {
        FUN_8000bb18(0,0x7e);
        bVar1 = true;
        iVar2 = FUN_8002e0fc(&local_48,&local_44);
        piVar4 = (int *)(iVar2 + local_48 * 4);
        for (; local_48 < local_44; local_48 = local_48 + 1) {
          if ((*piVar4 != param_1) && (*(short *)(*piVar4 + 0x46) == 0x282)) {
            iVar2 = *(int *)(iVar2 + local_48 * 4);
            (**(code **)(**(int **)(iVar2 + 0x68) + 0x20))(iVar2,6);
            break;
          }
          piVar4 = piVar4 + 1;
        }
        dVar6 = (double)FUN_8001461c();
        local_20 = (longlong)(int)(dVar6 / (double)FLOAT_803e55d8);
        FUN_801dc8d4(&DAT_803dc068,(int)(dVar6 / (double)FLOAT_803e55d8));
      }
      if (!bVar1) {
        FUN_8000bb18(0,0x109);
      }
    }
  }
  FUN_8002fa48((double)*(float *)(puVar5 + 2),(double)FLOAT_803db414,param_1,auStack64);
  FUN_80037b40(param_1,8,0xff,0xff,0x78,0x129,&DAT_803ddc08);
  return;
}

