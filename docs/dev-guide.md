# MediaFuzzer-Replica 开发指南总览

本文档为 MediaFuzzer-Replica 项目的逐模块开发文档索引。每个子文档包含模块职责、接口规格、数据结构、实现策略、跨模块依赖、错误处理、实现步骤和测试计划。

---

## 文档索引

| 模块 | 文档 | 里程碑 |
|------|------|--------|
| 全局配置 & 文件格式骨架 | [config.md](config.md) | M1 |
| APK 解包与 JNI 签名提取 | [apk_io.md](apk_io.md) | M1 |
| LLM 多媒体函数筛选 | [llm_interface.md](llm_interface.md) | M2 |
| Qiling 模拟执行环境 | [emulation.md](emulation.md) | M3 |
| 模糊测试引擎 | [fuzzing.md](fuzzing.md) | M4 |
| 内存安全检测 | [memory_safety.md](memory_safety.md) | M5 |
| 结果报告生成 | [reporter.md](reporter.md) | M6 |
| C/C++ 辅助工具 | [tools.md](tools.md) | M3-M4 |
| 主流水线串联 | [pipeline.md](pipeline.md) | M6 |
| 测试策略与用例 | [testing.md](testing.md) | 全阶段 |

---

## 项目架构概览

```
APK集合
  │
  ▼
┌─────────────┐    ┌──────────────┐
│  apk_io     │───▶│ llm_interface│
│ (提取签名)   │    │ (多媒体筛选)  │
└─────────────┘    └──────┬───────┘
                          │ 多媒体函数清单
                          ▼
┌─────────────────────────────────────────┐
│              fuzzing 主循环              │
│  ┌───────────┐  ┌─────────┐  ┌───────┐ │
│  │ emulation │  │ fuzzing │  │memory │ │
│  │ (Qiling)  │  │ (变异)   │  │safety│ │
│  └───────────┘  └─────────┘  └───────┘ │
└────────────────────┬────────────────────┘
                     │ 崩溃/异常
                     ▼
              ┌─────────────┐
              │  reporter   │
              │ (报告生成)   │
              └─────────────┘
```

## 开发里程碑

| 阶段 | 主要任务 | 完成标准 | 依赖 |
|------|---------|---------|------|
| M1 | config + apk_io | 正确提取100个真实APK的所有JNI签名 | 无 |
| M2 | llm_interface | 对标注数据集筛选召回率 > 90% | M1 |
| M3 | emulation + tools (harness) | 极简JNI SO稳定运行1000轮不崩溃 | M1 |
| M4 | fuzzing (全覆盖率反馈+格式感知) | 触发 CVE-2019-11932 | M2, M3 |
| M5 | memory_safety | CWE122/415/416检出不低于论文数据 | M3 |
| M6 | pipeline + reporter + 全流程 | 500 APK 稳定运行并输出报告 | M1-M5 |

## 通用编码约定

- Python 3.10+，使用 type hints
- 日志统一使用 `logging` 模块，logger 名为 `mediafuzzer.<module>`
- 异常体系：所有模块自定义异常继承自 `MediaFuzzerError`
- 配置读取：所有模块通过 `config.settings` 导入配置，不硬编码路径
- 文件 I/O：所有输出写入 `output/<timestamp>/` 目录，保证可重现

## 注意
 - python 3.12 已配置在当前目录的虚拟环境.venv下，可直接使用，相关的依赖后续也应该安装在该虚拟环境中
 - 其他需要的环境例如Qiling、LLM等，安装在当前项目下即可

