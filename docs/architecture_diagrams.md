# Architecture Diagrams

## Use Case Diagram

```
                    +-------------------+
                    |   User (Browser)  |
                    +---------+---------+
                              |
          +-------------------+-------------------+
          |                   |                   |
          v                   v                   v
    +-----------+      +-------------+      +-----------+
    | Check URL |      | View Result |      | Upload    |
    |           |      |             |      | HTML File |
    +-----------+      +-------------+      +-----------+
          |
          v
    +------------------+
    | Phishing Detection|
    | System           |
    +------------------+
          |
     +----+----+
     |         |
     v         v
+--------+ +--------+
| Check  | | Check  |
| URL    | | HTML   |
| Feats  | | Content|
+--------+ +--------+
```

## Sequence Diagram

```
User            Frontend           API              Model
 |                 |                |                 |
 |-- Enter URL --> |                |                 |
 |                 |-- POST /predict -->|                 |
 |                 |                |-- extract URL features -->|
 |                 |                |-- (optional) extract DOM/text -->|
 |                 |                |-- forward() -->|
 |                 |                |                 |
 |                 |<-- prediction result --|                 |
 |<-- Display result --|                |                 |
 |                 |                |                 |
 |-- (optional) upload HTML --> |                |                 |
 |                 |-- POST /predict (with HTML) -->|                 |
 |                 |                |-- extract DOM/text -->|
 |                 |                |-- forward() -->|
 |                 |                |                 |
 |                 |<-- prediction result --|                 |
 |<-- Display result with brand info --|                |                 |
```

## Entity-Relationship Diagram

```
+----------------+     +------------------+
|   Dataset      |     |  Feature         |
+----------------+     +------------------+
| id (PK)        |     | feature_id (PK)  |
| name           |     | name             |
| source         |     | type (URL/DNS/SSL/DOM) |
| n_samples      |     | dimension        |
| n_phishing     |     | extractor        |
| n_benign       |     +------------------+
+----------------+           |
       |                      |
       v                      v
+----------------+     +------------------+
|  Sample        |     |  Feature Value   |
+----------------+     +------------------+
| sample_id (PK) |     | sample_id (FK)   |
| dataset_id (FK)|     | feature_id (FK)  |
| url            |     | value            |
| html_path      |     | is_padded (bool) |
| label (0/1)    |     +------------------+
+----------------+
       |
       v
+----------------+
|  Prediction    |
+----------------+
| pred_id (PK)   |
| sample_id (FK) |
| model_name     |
| probability    |
| is_phishing    |
| brand_detected |
| timestamp      |
+----------------+
```

## Model Architecture

```
                    +------------------------------------------+
                    |          PhishingDetector                 |
                    +------------------------------------------+
                    |                                          |
   tabular(12) -->  |  TabTransformer -----> 128-dim ---------|----+
                    |                                          |    |
   input_ids   -->  |  ModernBERT --------> 768-dim CLS ---+  |    |
                    |                                       |  |    |
   dom(64)     -->  |  Linear+ReLU+LN ----> 64-dim --------+  |    |
                    |                          |               |    |
                    |                    concat [832]          |    |
                    |                          |               |    |
                    |              GatedFusion(128, 832)       |    |
                    |                          |               |    |
                    |                   FC(960->256->64->1)    |    |
                    |                          |               |    |
                    +--------------------|-----|--------------+----+
                                         |     |
                                         v     v
                                     logits (raw)
```

## 5-Fold Cross Validation

```
Dataset
   |
   v
+----+----+----+----+----+
|Fold1|Fold2|Fold3|Fold4|Fold5|
+----+----+----+----+----+
   |    |    |    |    |
   v    v    v    v    v
+----+----+----+----+----+
|Test|Train|Train|Train|Train|  -> Model 1
+----+----+----+----+----+
|Train|Test|Train|Train|Train|  -> Model 2
+----+----+----+----+----+
|Train|Train|Test|Train|Train|  -> Model 3
+----+----+----+----+----+
|Train|Train|Train|Test|Train|  -> Model 4
+----+----+----+----+----+
|Train|Train|Train|Train|Test|  -> Model 5
+----+----+----+----+----+
     |    |    |    |    |
     v    v    v    v    v
   +------------------------+
   | Average metrics (mean) |
   +------------------------+
```

Note: Cả 3 model (Baseline 1, Baseline 2, Proposed) đều dùng 5-fold CV với cùng split/seed.
