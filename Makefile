all:
	docker compose -f network/docker-compose.yml up --build -d 

logs:
	docker logs attacker
	docker logs victim1
	docker logs victim2

stop:
	docker compose -f network/docker-compose.yml stop 

clean: stop
	docker compose -f network/docker-compose.yml rm

fclean: clean
	docker compose -f network/docker-compose.yml down

re: fclean all

attacker:
	docker exec -it attacker /bin/bash

victim1:
	docker exec -it victim1 /bin/bash

victim2:
	docker exec -it victim2 /bin/bash

.Phony: all logs stop clean fclean re attacker victim1 victim2