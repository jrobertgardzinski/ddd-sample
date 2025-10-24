# ddd-sample
A sample project for learning DDD and other trends in practise.

## New java microservice recipe
Level 1
1. [entity] Design entities. 
   * Each entity has field of dedicated class in vo packages
   * Any external resource is of class String and starts with "ext" and the value point out to the resource URI. At least for now.
2. [vo] A place for entities fields

Level 2
1. [repository] Persistence

Level 3
1. [service] Logic that cannot be handled by VO. If it relies on repositories consider adding them first.
2. [event] output of service methods

Level 4 
1. [aggregate] Grouping entities

Have you noticed lack of [service] in the Level 2? I think there is no need for creating service that's in fact a delegates repository methods. 

# Sources
The very first video on the topic: https://www.youtube.com/watch?v=rolfJR9ERxo