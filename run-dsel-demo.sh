#!/bin/bash
# ModelMux DSEL Demo - Shows DSEL working

SESSION="modelmux-dsel"
tmux kill-session -t $SESSION 2>/dev/null || true
tmux new-session -d -s $SESSION -n "dsel"
tmux split-window -h -t $SESSION

# Left pane: Start agent8888 server
tmux send-keys -t $SESSION:0.0 "cd /Users/jim/work/litebike" Enter
tmux send-keys -t $SESSION:0.0 "echo '=== DSEL Server (agent8888) ==='" Enter
tmux send-keys -t $SESSION:0.0 "./target/debug/agent8888 2>&1" Enter

sleep 2

# Right pane: Test DSEL endpoints
tmux send-keys -t $SESSION:0.1 "cd /Users/jim/work/litebike" Enter
tmux send-keys -t $SESSION:0.1 "echo '=== DSEL Client Tests ==='" Enter
tmux send-keys -t $SESSION:0.1 "sleep 1" Enter
tmux send-keys -t $SESSION:0.1 "echo && echo '1. Health:' && curl -s http://localhost:8888/health | jq ." Enter
tmux send-keys -t $SESSION:0.1 "echo && echo '2. Models:' && curl -s http://localhost:8888/v1/models | jq '.data | length'" Enter
tmux send-keys -t $SESSION:0.1 "echo && echo '3. Chat:' && curl -s -X POST http://localhost:8888/v1/chat/completions -H 'Content-Type: application/json' -d '{\"model\":\"kilo_code/minimax-minimax-m2.5:free\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}' | jq '.choices[0].message.content'" Enter

tmux attach-session -t $SESSION
