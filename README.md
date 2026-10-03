# warcindex

本地的 WARC 网页存档读取与磁盘索引库（Python 3.12，纯标准库，无网络服务）。
为回放服务直接 `import` 使用而设计：读入 WARC 记录、把索引持久化到磁盘、
按条件确定性查询，并在取正文时自动解析 revisit 记录指向的原始响应。

## 功能

- **流式读取**：数据按任意大小的字节块喂入，记录体不整块进内存；
  内存占用不随 WARC 文件大小增长。识别 `response`、`revisit`、`warcinfo`、
  `metadata`（以及 `request`、`resource` 等其余标准类型）。
- **磁盘索引**：元数据存入一个目录下的 SQLite 数据库（`warcindex.db`），
  WARC 正文始终留在原文件里，用 `(文件, 偏移, 长度)` 定位。
- **确定性查询**：按 target URI、抓取时间、记录 ID、payload digest 组合查询；
  结果按 `(URI, 抓取时间, 记录 ID)` 全序返回，每次一致。同一 URI 不同时间的
  抓取是不同记录，不会合并。
- **revisit 解析**：查询结果中的 revisit 只有元数据；调用 `resolve()` 时返回
  其指向的原始 HTTP 头与正文，结果中 `payload_record_id` 标明正文实际来源。
  以下情况明确抛出区分类型的错误，而不会伪装成正常结果：

  - 目标记录不在索引中 → `RevisitTargetNotFoundError`
  - digest 对不上（存储值或重新计算的正文 digest）→ `RevisitDigestMismatchError`
  - 目标或 revisit 本身被截断 → `RevisitTargetTruncatedError`
  - 不认识的 revisit profile → `UnsupportedRevisitProfileError`

- **结果自带定位与告警**：每条结果含原始文件中的偏移、长度、解析告警；
  revisit 结果额外含正文来源记录 ID。
- **可重开**：索引 `save()` 后，换新进程 `open()` 重查，结果完全一致。
- **校验入口**：`validate_index()` 流式核对源文件、偏移/长度、digest 与
  revisit 链，返回带 `error`/`warning` 分级的报告。

## 安装

需要 Python 3.12（无第三方运行时依赖）。

```bash
# 从源码目录安装
python -m pip install .

# 带测试依赖
python -m pip install ".[test]"
```

## 使用

### 1. 读取（不建索引）

```python
from warcindex import iter_records

for info in iter_records("crawl.warc", chunk_size=1024 * 1024):
    print(info.record_type, info.target_uri, info.date,
          info.offset, info.length, info.computed_payload_digest)
```

`iter_records` 接受路径或任意二进制文件对象；底层是一个 push 式的
`WarcStreamParser`，数据被切成任意大小的块都能解析（记录可能横跨多个块）：

```python
from warcindex import WarcStreamParser
from warcindex.models import RecordBegin, PayloadData, RecordEnd

parser = WarcStreamParser()
for chunk in byte_source:            # 任意大小的 bytes 块
    for event in parser.feed(chunk):
        ...                          # RecordBegin -> PayloadData* -> RecordEnd
for event in parser.feed_eof():
    ...
```

### 2. 建索引并保存

```python
from warcindex import WarcIndex

idx = WarcIndex.open_or_create("./idx-dir")
idx.add_path("crawl-2026-01.warc")
idx.add_path("crawl-2026-02.warc")
idx.save()      # 提交并 fsync；之后可在其他进程打开
idx.close()
```

重复添加同一个未变化的文件是空操作；文件大小变化会抛 `FileChangedError`；
跨文件出现重复 `WARC-Record-ID` 会抛 `DuplicateRecordIdError`。

### 3. 查询

```python
idx = WarcIndex.open("./idx-dir")

rows = idx.query(uri="https://example.com/")                    # 按 URI
rows = idx.query(uri="https://example.com/",
                 date="2026-01-15T08:00:00Z")                  # 再加时间
view = idx.get("urn:uuid:a1b2-...")                             # 按记录 ID
rows = idx.query(payload_digest="sha1:U4QU...")                # 按 digest
rows = idx.query(record_type="response")                       # 也可组合

v = rows[0]
v.offset, v.length, v.file_path      # 记录在原 WARC 中的定位
v.truncated, v.trunc_reason          # 截断信息
v.warnings                           # 解析告警（digest 不符、裸 LF 等）
```

### 4. 取正文（含 revisit）

```python
with idx.resolve(view) as payload:           # 也可直接传记录 ID
    payload.http_status                       # HTTP 状态码
    payload.http_headers                      # HTTP 头（大小写不敏感）
    body = payload.read()                     # 实体正文（自动解 chunked）
    payload.payload_record_id                 # 正文实际来自哪条记录
    payload.is_revisit                        # 是否为 revisit 解析结果
```

对普通记录，`payload_record_id` 是它自己；对 revisit，是被指向的原始响应。
在截断记录上调用 `resolve()` 会抛 `TruncatedRecordError`，不会把半截正文
当作成功结果返回。

### 5. 校验

```python
from warcindex import validate_index

report = validate_index(idx)
report.ok                  # False 表示存在 error 级问题
for issue in report:
    print(issue)           # [ERROR] digest-mismatch ... / [WARNING] truncated ...
```

校验是流式的：逐记录重读磁盘、重算 payload digest、验证 revisit 解析链，
不会把 WARC 整体读进内存。也可以用
`validate_index(idx, raise_on_error=True)` 在第一个错误处直接抛出。

## 错误类型

所有异常都继承自 `warcindex.WarcError`：

| 异常 | 场景 |
| --- | --- |
| `WarcIOError` | WARC 文件无法打开/读取 |
| `WarcFormatError` / `WarcVersionError` / `WarcHeaderError` | 字节流不符合 WARC 格式 |
| `CompressionUnsupportedError` | 输入是 gzip（本版只收未压缩 WARC） |
| `IndexNotFoundError` / `IndexFormatError` | 索引目录不存在或版本不兼容 |
| `FileChangedError` | 已索引文件大小发生变化 |
| `DuplicateRecordIdError` | 重复的 `WARC-Record-ID` |
| `RecordNotFoundError` | 按 ID 查不到记录 |
| `TruncatedRecordError` | 记录被截断（拒绝当作正常正文返回） |
| `DigestMismatchError` | 声明 digest 与实际正文不符 |
| `RevisitTargetNotFoundError` | revisit 目标缺失 |
| `RevisitDigestMismatchError` | revisit digest 与目标正文不符 |
| `RevisitTargetTruncatedError` | revisit 目标被截断 |
| `UnsupportedRevisitProfileError` | 不支持的 revisit profile |

## 设计要点

- **记录长度**：版本行起到块结束为止，不含记录之间的 `CRLF CRLF`；换分块
  大小重跑得到的偏移完全相同。
- **digest**：内部统一为 `算法:大写 base32`（WARC 惯例）。HTTP 记录对实体
  正文（去掉 `Transfer-Encoding: chunked` 成帧）做摘要；非 HTTP 记录对整个
  块摘要。建索引时以声明 digest 的算法为准，同时保留声明值与实算值，两者
  不符会进入记录告警。
- **revisit 选择规则**：

  - `identical-payload-digest`：优先使用 `WARC-Refers-To` 指针；否则选同
    URI、抓取时间不晚于 revisit 的最近 `response`。随后强制校验
    “revisit 声明 digest == 目标存储 digest == 重新计算的目标正文 digest”。
  - `server-not-modified`：优先使用 `WARC-Refers-To`；缺省时回退到同 URI
    最近的 response，并同样做 digest 证明。

- **内存**：解析器只保留“当前分块 + 一个记录头（上限 16 MiB）”；HTTP 头与
  chunked 解码都是增量的；正文读取器是受限范围的文件流，可用
  `payload.stream()` 分块读大文件。

## 限制

- 本版只索引**未压缩** WARC（WARC/1.0、WARC/1.1）。遇到 gzip 魔数会抛
  `CompressionUnsupportedError`；请先解压或在上游透明 gunzip。
- 不解压实体的 `Content-Encoding`（gzip/deflate 实体按原始实体字节摘要）。
- 不提供命令行与界面，仅作为库使用。

## 运行测试

```bash
python -m pip install ".[test]"
python -m pytest
```

## 许可证

MIT
