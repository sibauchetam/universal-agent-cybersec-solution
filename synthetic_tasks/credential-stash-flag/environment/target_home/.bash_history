git push origin main
curl -s https://api.internal.local/health
export API_TOKEN=$(echo aDFzdDByeQ== | base64 -d)   # part2
docker compose up -d
