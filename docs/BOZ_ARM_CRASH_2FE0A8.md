# BOZ: proxima falha ARM apos restaurar console.bin

## Base verificavel

Imagem de referencia XE3U:
`dbf342663fcd8c7f8fcedced1693eb532cbea8053ef472c0cb837323f3b57d95`.

O arquivo DTRZ `blackops_loader.dz` do APK recuperado contem
`console.bin` com **33.395 bytes**, SHA-256
`4c0137921d2fcba4fd08166fd7ae12193f5e130b4528f2ff5c3bf4f8637ae91a`.

A copia publica idêntica e baixada durante a execucao, verificada pelo
SHA-256 `41f00e3418ca2833e2bc5cb936c7600083b7c757500e0646912d92fda899a597`.
O arquivo binario nao e incluido neste repositorio.

## Resultado da execucao real

Render `dep-db54vcfg0jfs73b5mc70` com DTRZ instalado:
BOZ avancou alem do crash Thumb em `DB31E` e parou em
`PC=0x4A2FE0A8` (`BOZ+0x2FE0A8`, modo ARM).
Signal 11: acesso ao endereco `0x2c`.
O jogo ainda NAO esta jogavel.

## Desmontagem

```asm
2FE088: push {r0,r1,r4,r5,r6,lr}
2FE08C: mov r4,r0
...
2FE0A4: blx 0x20F26C
2FE0A8: ldrh r3,[r4,#44]    ; fault se r4 == 0
```

O endereco de falha `0x2c` equivale a `r4=0`.
Ha dois chamadores ARM diretos na imagem:
- `0x2FFA30: BL 0x2FE088` — recebe objeto em r0 de r4,
  obtendo r1 do retorno de uma chamada virtual anterior.
- `0x300444: BL 0x2FE088` — recebe objeto em r0 de r4,
  igualmente depois de uma chamada virtual.

Isso nao prova qual chamador participou da falha. A nova instrumentacao
ARM inclui ambas as instrucoes, a entrada `2FE088` e a instrucao
`2FE0A8`; registrara registradores e LR reais.

**Nao** mascarar o bug colocando objeto falso ou pulando a
instrucao. Precisamos rastrear a origem do r0 nulo e as rotinas
que deveriam fornecer o objeto antes de reconstruir a correcao.
