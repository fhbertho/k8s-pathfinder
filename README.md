# Kubernetes Microsegmentation and Attack Path Visualizer (k8s-pathfinder)

Uma ferramenta de análise e visualização de segurança projetada para avaliar a postura de clusters Kubernetes, descobrir vetores de movimentação lateral, calcular grafos de caminhos de ataque (attack paths) com múltiplos saltos visando o Master Node e simular políticas de microssegmentação.

## Visão Geral

Em ambientes modernos de contêineres, topologias de rede planas e configurações permissivas de RBAC (Role-Based Access Control) frequentemente permitem que atacantes internos ou pods comprometidos escalem privilégios e tomem o controle do control plane (Master Node).

Este projeto analisa de forma estática e dinâmica manifestos Kubernetes, permissões da API server e políticas de rede para:
1. Analisar configurações e o estado de execução do cluster Kubernetes.
2. Construir um grafo direcionado representando entidades (Pods, ServiceAccounts, Roles, ClusterRoles, Nodes, Secrets) e seus relacionamentos.
3. Calcular caminhos de ataque viáveis que levam ao comprometimento do cluster.
4. Simular e validar regras de microssegmentação para aplicar o princípio do menor privilégio (*least privilege*).

---

## Arquitetura Principal

```
+------------------------------------------------------------+
|                     Fontes de Entrada                      |
|   (Manifestos YAMLs K8s / API Server / RBAC / NetPol)      |
+-----------------------------+------------------------------+
                              |
                              v
+------------------------------------------------------------+
|                  Motor de Grafos e Parser                  |
|     - Entidades: Pod, ServiceAccount, Role, Node, Secret   |
|     - Arestas: EXEC_EXEC, TOKEN_MOUNT, RBAC_BIND, NET_ACC  |
+-----------------------------+------------------------------+
                              |
        +---------------------+---------------------+
        |                                           |
        v                                           v
+-------------------------------+           +-------------------------------+
|     Analisador de Ataque      |           | Simulador de Microssegmentação|
| - Dijkstra / Menor Caminho    |           | - Aplicação de NetworkPolicy  |
| - Matriz de Escalação Priv.   |           | - Verificação de Isolamento   |
+-------------------------------+           +-------------------------------+
        |                                           |
        +---------------------+---------------------+
                              |
                              v
+------------------------------------------------------------+
|                    Saída e Relatórios                      |
|     - Relatório CLI / Exportação JSON / Interface Web      |
+------------------------------------------------------------+
```

---

## Principais Funcionalidades

- **Mapeamento Automatizado de RBAC e Service Accounts**: Identifica Roles e ClusterRoles excessivamente permissivas associadas a ServiceAccounts padrão ou vulneráveis.
- **Geração de Grafos de Ataque**: Modela cenários de movimentação lateral, incluindo vetores de escape de contêiner, coleta de credenciais de secrets montadas e permissões excessivas na API (`create pods/exec`, `bind`, `impersonate`).
- **Avaliador de Políticas de Microssegmentação**: Testa o isolamento atual de namespaces e NetworkPolicies para detectar falhas de segmentação e vazamento de tráfego lateral.
- **Pontuação de Risco de Comprometimento do Master Node**: Calcula uma pontuação de risco determinística para cada ponto de entrada com base na profundidade de privilégios e extensão do caminho até o control plane.

---

## Tecnologias Utilizadas

- **Linguagem**: Python 3.10+
- **Processamento de Grafos**: NetworkX
- **Backend / API**: FastAPI, Uvicorn
- **SDK Kubernetes**: `kubernetes` python client / Parsers YAML (`PyYAML`)
- **Interface Visual**: Frontend interativo com Cytoscape.js

---

## Instalação e Configuração

### Pré-requisitos
- Python 3.10 ou superior
- Acesso a um cluster Kubernetes (minikube, kind ou cluster remoto) ou um diretório contendo manifestos de implantação do Kubernetes.

### Clonar e Instalar Dependências
```bash
git clone https://github.com/fhbertho/k8s-pathfinder.git
cd k8s-pathfinder

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## Como Usar

### 1. Executar a Aplicação Web
Inicie o servidor backend FastAPI com interface interativa:
```bash
cd backend
python3 main.py
```
Acesse a interface no seu navegador em: `http://localhost:8000`

### 2. Análise de Manifestos Estáticos
Envie ou aponte arquivos de manifesto YAML do Kubernetes para mapear potenciais escalações de privilégio e exposição de rede.

### 3. Simulação e Remediação de Microssegmentação
Gere e teste NetworkPolicies sugeridas com base no grafo de ataque calculado para bloquear canais de movimentação lateral.

---

## Exemplo de Saída

```text
[INFO] Inicializando Auditoria de Segurança do Cluster K8s...
[INFO] Carregados 42 Pods, 14 ServiceAccounts, 8 ClusterRoles, 3 NetworkPolicies.
[WARN] Vulnerabilidade Encontrada: ServiceAccount 'default:ci-runner' associada à ClusterRole 'cluster-admin' via RoleBinding.
[WARN] Caminho de Ataque Descoberto:
  [Pod: web-app-pod] 
    --> (Montagem de Token / Extração de Secret) 
  [ServiceAccount: ci-runner] 
    --> (RBAC ClusterRoleBinding: cluster-admin) 
  [Alvo: Master Node / Control Plane API Server]
[SUMMARY] Nível de Risco: CRÍTICO (Tamanho do Caminho: 2 saltos)
```

---

## Roadmap

- [ ] Implementação de descoberta de tráfego em tempo de execução baseada em eBPF para complementar o mapeamento estático.
- [ ] Integração com OPA / Gatekeeper para gerar automaticamente políticas de remediação.
- [ ] Melhorias no painel interativo Cytoscape.js para filtros avançados de busca de caminhos.

---

## Contribuição

Contribuições, sugestões e relatórios de problemas são muito bem-vindos. Sinta-se à vontade para abrir uma *issue* ou enviar um *pull request*.

---

## Licença

Distribuído sob a licença GPL-3.0. Consulte o arquivo `LICENSE` para mais informações.
