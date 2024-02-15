all:
	docker compose -f network/docker-compose.yml up --build -d 

logs:
	docker logs attacker
	docker logs victim1
	docker logs victim2

stop:
	docker compose -f network/docker-compose.yml stop 

clean: stop
	docker compose -f network/docker-compose.yml down

fclean: clean
	docker system prune -af

re: fclean all

attacker:
	docker exec -it attacker /bin/bash

attacker2:
	docker exec -it attacker2 /bin/bash

victim1:
	docker exec -it victim1 /bin/bash

victim2:
	docker exec -it victim2 /bin/bash

.Phony: all logs clean fclean