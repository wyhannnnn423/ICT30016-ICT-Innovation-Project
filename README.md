# Campus IDS

ICT30016 (ICT Innovation Project) — Campus Network Intrusion Detection System.

轻量级、AI 驱动的校园网络入侵检测系统：捕获网络流量、基于 IPv4 flow 聚合特征、
使用 Isolation Forest 进行无监督异常检测，并通过 Flask 看板实时展示告警。

## 团队

- Jane Yan Zhen YU（团队负责人）
- Yan Han WONG (Han)
- Neville
- Bruce Gee Yick WONG

## 项目结构

```
campus-ids/
├── suricata/           # Suricata 日志解析，提取 flow 特征
│   └── read_suricata_flows.py
├── model/               # 异常检测模型训练与预测
│   ├── train_model.py
│   └── predict.py
├── data/                # 流量特征 / 检测结果 CSV（不进版本库，见 .gitignore）
└── dashboard/           # Flask 实时看板
    ├── app.py
    └── templates/
        └── dashboard.html
```

## 使用流程

1. **采集流量特征**（需要 Suricata 已配置 eve-log flow 输出）
   ```bash
   python suricata/read_suricata_flows.py --input /var/log/suricata/eve.json --output data/suricata_flow_features.csv
   ```

2. **训练模型**
   ```bash
   python model/train_model.py --input data/suricata_flow_features.csv --model_out model/ids_model.joblib
   ```

3. **检测异常**
   ```bash
   python model/predict.py --input data/suricata_flow_features.csv \
                            --model model/ids_model.joblib \
                            --scaler model/ids_scaler.joblib \
                            --output data/flagged_anomalies.csv
   ```

4. **启动看板**
   ```bash
   cd dashboard
   python app.py
   ```
   浏览器打开 http://127.0.0.1:5000

## 安装依赖

```bash
pip install -r requirements.txt
```

## Git 工作流

- `main` 分支为稳定版本
- 各功能开发使用 feature branch（如 `feature/suricata-parser`）
- 合并前需通过 Pull Request review

## 备注

本仓库为正式开发仓库，原型/演示代码保留在 `ids_demo` 仓库中，互不影响。
