# BOZ: serializador com FILE* nulo — evidencias de 2026-10-10

## Binario realmente analisado

Imagem XE3U recuperada `boz.s3e.unpacked`; SHA-256
`dbf342663fcd8c7f8fcedced1693eb532cbea8053ef472c0cb837323f3b57d95`.
Os offsets sao relativos a imagem, independentemente do endereco de carga.

## Caminho observado sob QEMU-ARM no Render

1. O ponteiro solicitado pela segunda chamada e preservado de
   `DB306 -> DB31C -> DA728 -> D8F0E`.
2. A arvore de manipuladores em `D8F0E` contem entradas, mas a
   chave dessa chamada nao e encontrada (sentinela selecionada).
3. `DB2FA` chama o serializador `257B98`. Uma chamada nativa
   `s3eFileRead(buffer,4,1,FILE*)` sobre o buffer exato recebeu
   `file=0` e retornou zero elementos; EOF=0, ferror=0.
4. Uma sonda colocada **depois** do carregamento ARM em `257BD0`
   mediu em `257BD4`: ponteiro da estrutura global
   `0x4A49BB90`, modo de leitura 1 e `FILE*=0`.
   Nessa mesma execucao, o rastreador nao observou
   `s3eFileOpen` nem `s3eFileOpenFromMemory`.

Os enderecos de ponteiros dinamicos variam entre execucoes. O local
da estrutura global e calculado a partir de instrucoes PIC verificadas.

## Onde o arquivo deveria ser instalado

Desmontagem ARM, independentemente confirmada a partir do S3E:

- `25812C`: funcao recebe nome do arquivo (r0), modo (r1).
- `258144/25815C`: escolhe as strings `rb` ou `wb`.
- `25814C/258164`: chama o helper `24B744`.
- `24B744 -> 24B5A8 -> PLT 0x450`: o import da PLT
  0x450 e **s3eFileOpen**, resolvido pela tabela XE3U de fixups.
- `258170`: `str r0,[r3,#8]`; grava o FILE* retornado no
  campo +8 da estrutura global `0x49BB90`.
- `257BD0`: `ldr r3,[ip,#8]`; le o mesmo FILE*.
- `257BE0`: chama PLT `0x77C = s3eFileRead` se
  o flag indicar modo leitura.

Equivalente comportamental **parcial** (nao texto-fonte original):

```cpp
// Descritivo: o helper de caminhos interno nao esta reconstruido aqui.
void preparar_stream(Serializador &s, const char* nome, bool ler) {
    s.arquivo = abrir_arquivo_via_helper(nome, ler ? "rb" : "wb");
}
```

A causa definitiva do FILE* nulo ainda nao esta estabelecida:
o programa pode nao ter chamado a inicializacao, pode ter pedido
um caminho ausente, ou a abertura pode ter falhado por outro motivo.
**Nao** fabricar FILE* ou inserir chave ficticia na arvore.

## Proxima verificacao

`src/main.c` possui sondas ARM nas instrucoes **25812C** e
**258170** e uma sonda ARM diferida em **257BD4**, habilitadas
por `BOZ_TRACE_SELECTOR_STREAM=1`. `remote_build.py` exporta
`[SERIALIZER_OPEN_RESULT]` com contagens de entradas e atribuicoes
nulas/nao nulas. Testes acompanham o analisador.

O runner atual usa um S3E de referencia e nao inclui
necessariamente todos os recursos proprietarios do jogo.
Um resultado de recurso ausente neste ambiente nao deve ser
atribuido automaticamente ao APK original.
