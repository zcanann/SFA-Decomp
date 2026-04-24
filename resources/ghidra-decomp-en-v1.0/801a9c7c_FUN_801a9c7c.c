// Function: FUN_801a9c7c
// Entry: 801a9c7c
// Size: 496 bytes

void FUN_801a9c7c(short *param_1,int param_2)

{
  int iVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0x5c);
  *(undefined **)(param_1 + 0x5e) = &LAB_801a9468;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1f) << 8;
  *puVar2 = 0;
  FUN_80037200(param_1,0x2e);
  iVar1 = *(int *)(param_2 + 0x14);
  if (iVar1 == 0x43e1f) {
    *(undefined2 *)(puVar2 + 8) = 0x9a3;
    *(undefined2 *)(puVar2 + 10) = 0x99c;
  }
  else if (iVar1 < 0x43e1f) {
    if (iVar1 == 0x41a5c) {
      *(undefined2 *)(puVar2 + 8) = 0x868;
      *(undefined2 *)(puVar2 + 10) = 0x85a;
    }
    else if (iVar1 < 0x41a5c) {
      if (iVar1 != 0x41a5a) {
        if (iVar1 < 0x41a5a) {
          if (0x41a58 < iVar1) {
            *(undefined2 *)(puVar2 + 8) = 0x867;
            *(undefined2 *)(puVar2 + 10) = 0x858;
          }
        }
        else {
          *(undefined2 *)(puVar2 + 8) = 0x866;
          *(undefined2 *)(puVar2 + 10) = 0x856;
        }
      }
    }
    else if (iVar1 == 0x43e04) {
      *(undefined2 *)(puVar2 + 8) = 0x9a2;
      *(undefined2 *)(puVar2 + 10) = 0x99a;
    }
    else if ((iVar1 < 0x43e04) && (iVar1 < 0x41a5e)) {
      *(undefined2 *)(puVar2 + 8) = 0x869;
      *(undefined2 *)(puVar2 + 10) = 0x864;
    }
  }
  else if (iVar1 == 0x4b26e) {
    *(undefined2 *)(puVar2 + 8) = 0xd4d;
    *(undefined2 *)(puVar2 + 10) = 0xd4b;
  }
  else if (iVar1 < 0x4b26e) {
    if (iVar1 == 0x476ae) {
      *(undefined2 *)(puVar2 + 8) = 0x3d5;
      *(undefined2 *)(puVar2 + 10) = 0x3d2;
    }
    else if (iVar1 < 0x476ae) {
      if (iVar1 == 0x43e21) {
        *(undefined2 *)(puVar2 + 8) = 0x9a5;
        *(undefined2 *)(puVar2 + 10) = 0x9a0;
      }
      else if (iVar1 < 0x43e21) {
        *(undefined2 *)(puVar2 + 8) = 0x9a4;
        *(undefined2 *)(puVar2 + 10) = 0x99e;
      }
    }
  }
  else if (iVar1 == 0x4bea3) {
    *(undefined2 *)(puVar2 + 8) = 0xe21;
    *(undefined2 *)(puVar2 + 10) = 0xe10;
  }
  puVar2[1] = 0;
  return;
}

