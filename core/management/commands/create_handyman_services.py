from django.core.management.base import BaseCommand
from core.models import HandymanService

class Command(BaseCommand):
    help = 'Creates initial handyman service categories'

    def handle(self, *args, **kwargs):
        # List of common handyman services
        services = [
            {"name": "Plumbing", "description": "Fixing pipes, drains, faucets, toilets, and other plumbing issues", "icon": "fa-wrench"},
            {"name": "Electrical", "description": "Installation and repair of electrical systems, wiring, outlets, and fixtures", "icon": "fa-bolt"},
            {"name": "Carpentry", "description": "Woodworking, furniture repair, and custom carpentry projects", "icon": "fa-hammer"},
            {"name": "Painting", "description": "Interior and exterior painting services for homes and businesses", "icon": "fa-paint-roller"},
            {"name": "Cleaning", "description": "Deep cleaning, regular maintenance, and specialized cleaning services", "icon": "fa-broom"},
            {"name": "Gardening", "description": "Lawn care, gardening, landscaping, and plant maintenance", "icon": "fa-leaf"},
            {"name": "HVAC", "description": "Heating, ventilation, and air conditioning installation and repair", "icon": "fa-temperature-high"},
            {"name": "Appliance Repair", "description": "Repair and maintenance of household appliances", "icon": "fa-blender"},
            {"name": "Roofing", "description": "Roof installation, repair, and maintenance services", "icon": "fa-home"},
            {"name": "Flooring", "description": "Installation and repair of various flooring types", "icon": "fa-ruler"},
            {"name": "Locksmith", "description": "Lock installation, repair, and key duplication services", "icon": "fa-key"},
            {"name": "Moving", "description": "Packing, moving, and furniture assembly services", "icon": "fa-truck"},
            {"name": "Pest Control", "description": "Elimination and prevention of pests and insects", "icon": "fa-bug"},
            {"name": "Security Systems", "description": "Installation and maintenance of security systems and cameras", "icon": "fa-shield-alt"},
            {"name": "Window Repair", "description": "Window installation, repair, and glass replacement", "icon": "fa-window-maximize"},
            {"name": "Catering", "description": "Food preparation and service for events and parties", "icon": "fa-utensils"},
            {"name": "Event Planning", "description": "Planning and coordination of events and parties", "icon": "fa-calendar-check"},
            {"name": "Photography", "description": "Professional photography services for events and portraits", "icon": "fa-camera"},
        ]

        # Create services if they don't exist
        created_count = 0
        for service_data in services:
            service, created = HandymanService.objects.get_or_create(
                name=service_data["name"],
                defaults={
                    "description": service_data["description"],
                    "icon": service_data["icon"]
                }
            )
            if created:
                created_count += 1
                self.stdout.write(self.style.SUCCESS(f'Created service: {service.name}'))
            else:
                self.stdout.write(f'Service already exists: {service.name}')

        self.stdout.write(self.style.SUCCESS(f'Successfully created {created_count} handyman services'))
