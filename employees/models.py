from django.db import models

class Feedback(models.Model):
    content = models.TextField()

class Employee(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    position = models.CharField(max_length=100)

    def __str__(self):
        return self.name