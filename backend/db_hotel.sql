/*
SQLyog Ultimate v12.4.0 (64 bit)
MySQL - 8.0.30 : Database - db_hotel
*********************************************************************
*/

/*!40101 SET NAMES utf8 */;

/*!40101 SET SQL_MODE=''*/;

/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
CREATE DATABASE /*!32312 IF NOT EXISTS*/`db_hotel` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci */ /*!80016 DEFAULT ENCRYPTION='N' */;

USE `db_hotel`;

/*Table structure for table `clientes` */

DROP TABLE IF EXISTS `clientes`;

CREATE TABLE `clientes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_persona` int NOT NULL,
  `id_usuario` int NOT NULL,
  `id_cliente_perfil` int NOT NULL,
  `empresa` varchar(250) DEFAULT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `fecha_creado` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `fecha_actualizado` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `id_persona` (`id_persona`),
  KEY `id_usuario` (`id_usuario`),
  KEY `id_cliente_perfil` (`id_cliente_perfil`),
  CONSTRAINT `clientes_ibfk_1` FOREIGN KEY (`id_persona`) REFERENCES `personas` (`id`),
  CONSTRAINT `clientes_ibfk_2` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id`),
  CONSTRAINT `clientes_ibfk_3` FOREIGN KEY (`id_cliente_perfil`) REFERENCES `clientes_perfiles` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

/*Data for the table `clientes` */

insert  into `clientes`(`id`,`id_persona`,`id_usuario`,`id_cliente_perfil`,`empresa`,`estado`,`fecha_creado`,`fecha_actualizado`) values 
(1,2,2,1,NULL,'activo','2024-06-28 13:24:02',NULL),
(2,3,3,2,NULL,'activo','2024-06-28 13:24:03',NULL),
(3,9,1,1,'BCP','activo','2024-07-18 15:05:56',NULL),
(4,11,1,1,'BCP','activo','2024-07-18 15:07:02',NULL),
(5,16,1,1,'BCP','activo','2024-07-18 15:12:35',NULL),
(6,18,1,1,'BCP','activo','2024-07-18 15:15:13',NULL),
(7,20,1,1,'BCP','activo','2024-07-18 15:23:31',NULL),
(8,25,4,1,'Personal','activo','2024-07-18 20:39:33',NULL),
(9,26,5,1,'Personal','activo','2024-07-18 21:20:40',NULL);

/*Table structure for table `clientes_perfiles` */

DROP TABLE IF EXISTS `clientes_perfiles`;

CREATE TABLE `clientes_perfiles` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nombre` varchar(100) NOT NULL,
  `permisos` text NOT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `fecha_creado` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `fecha_actualizado` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

/*Data for the table `clientes_perfiles` */

insert  into `clientes_perfiles`(`id`,`nombre`,`permisos`,`estado`,`fecha_creado`,`fecha_actualizado`) values 
(1,'Cliente','{}','activo','2024-06-28 13:24:02',NULL),
(2,'Invitado','{}','activo','2024-06-28 13:24:02',NULL);

/*Table structure for table `comprobantes` */

DROP TABLE IF EXISTS `comprobantes`;

CREATE TABLE `comprobantes` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_reserva` int NOT NULL,
  `id_empleado` int NOT NULL,
  `tipo_comprobante` int NOT NULL,
  `estado` enum('activo','pendiente_pago','pagado','cancelado') DEFAULT 'activo',
  `fecha_creado` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `fecha_pagado` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `id_reserva` (`id_reserva`),
  KEY `id_empleado` (`id_empleado`),
  CONSTRAINT `comprobantes_ibfk_1` FOREIGN KEY (`id_reserva`) REFERENCES `reservas` (`id`),
  CONSTRAINT `comprobantes_ibfk_2` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

/*Data for the table `comprobantes` */

insert  into `comprobantes`(`id`,`id_reserva`,`id_empleado`,`tipo_comprobante`,`estado`,`fecha_creado`,`fecha_pagado`) values 
(1,1,1,1,'pagado','2024-06-28 13:24:03','2023-11-10 18:45:29');

/*Table structure for table `empleados` */

DROP TABLE IF EXISTS `empleados`;

CREATE TABLE `empleados` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_persona` int NOT NULL,
  `id_usuario` int NOT NULL,
  `id_empleado_perfil` int NOT NULL,
  `sueldo` decimal(10,2) NOT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `fecha_creado` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `fecha_actualizado` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `id_persona` (`id_persona`),
  KEY `id_usuario` (`id_usuario`),
  KEY `id_empleado_perfil` (`id_empleado_perfil`),
  CONSTRAINT `empleados_ibfk_1` FOREIGN KEY (`id_persona`) REFERENCES `personas` (`id`),
  CONSTRAINT `empleados_ibfk_2` FOREIGN KEY (`id_usuario`) REFERENCES `usuarios` (`id`),
  CONSTRAINT `empleados_ibfk_3` FOREIGN KEY (`id_empleado_perfil`) REFERENCES `empleados_perfiles` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

/*Data for the table `empleados` */

insert  into `empleados`(`id`,`id_persona`,`id_usuario`,`id_empleado_perfil`,`sueldo`,`estado`,`fecha_creado`,`fecha_actualizado`) values 
(1,1,1,1,1250.69,'activo','2024-06-28 13:24:02',NULL);

/*Table structure for table `empleados_perfiles` */

DROP TABLE IF EXISTS `empleados_perfiles`;

CREATE TABLE `empleados_perfiles` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nombre` varchar(100) NOT NULL,
  `permisos` text NOT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `fecha_creado` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `fecha_actualizado` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

/*Data for the table `empleados_perfiles` */

insert  into `empleados_perfiles`(`id`,`nombre`,`permisos`,`estado`,`fecha_creado`,`fecha_actualizado`) values 
(1,'Administrador','{}','activo','2024-06-28 13:24:02',NULL),
(2,'Recepcionista','{}','activo','2024-06-28 13:24:02',NULL),
(3,'Personal de limpieza','{}','activo','2024-06-28 13:24:02',NULL);

/*Table structure for table `habitaciones` */

DROP TABLE IF EXISTS `habitaciones`;

CREATE TABLE `habitaciones` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_tipohabitacion` int NOT NULL,
  `descripcion` varchar(250) NOT NULL,
  `nivel` varchar(25) NOT NULL,
  `numero_piso` varchar(25) NOT NULL,
  `precio` decimal(10,2) NOT NULL,
  `cantidad_camas` int NOT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `fecha_creado` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `fecha_actualizado` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `id_tipohabitacion` (`id_tipohabitacion`),
  CONSTRAINT `habitaciones_ibfk_1` FOREIGN KEY (`id_tipohabitacion`) REFERENCES `tipo_habitacion` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

/*Data for the table `habitaciones` */

insert  into `habitaciones`(`id`,`id_tipohabitacion`,`descripcion`,`nivel`,`numero_piso`,`precio`,`cantidad_camas`,`estado`,`fecha_creado`,`fecha_actualizado`) values 
(1,1,'habitación con agua caliente + tv','1','101',49.50,1,'activo','2024-06-28 13:24:03',NULL);

/*Table structure for table `personas` */

DROP TABLE IF EXISTS `personas`;

CREATE TABLE `personas` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nombre` varchar(100) NOT NULL,
  `apellido` varchar(100) NOT NULL,
  `tipo_documento` int DEFAULT NULL,
  `nrodocumento` varchar(30) DEFAULT NULL,
  `sexo` enum('F','M') DEFAULT NULL,
  `edad` varchar(5) DEFAULT NULL,
  `telefono` varchar(30) DEFAULT NULL,
  `fecha_nacimiento` varchar(30) DEFAULT NULL,
  `estado_civil` enum('soltero','casado','viudo') DEFAULT 'soltero',
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `fecha_creado` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `fecha_actualizado` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `tipo_documento` (`tipo_documento`,`nrodocumento`)
) ENGINE=InnoDB AUTO_INCREMENT=27 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

/*Data for the table `personas` */

insert  into `personas`(`id`,`nombre`,`apellido`,`tipo_documento`,`nrodocumento`,`sexo`,`edad`,`telefono`,`fecha_nacimiento`,`estado_civil`,`estado`,`fecha_creado`,`fecha_actualizado`) values 
(1,'Alex','Quispe',1,'12345678','M','30',NULL,NULL,'soltero','activo','2024-06-28 13:24:02',NULL),
(2,'Maria','Gonzales',1,'74567890','M','34',NULL,NULL,'soltero','activo','2024-06-28 13:24:02',NULL),
(3,'Susan','Torres',1,'87946521','M','48',NULL,NULL,'soltero','activo','2024-06-28 13:24:02',NULL),
(7,'Luis','Quispe',1,'98758938','M','30',NULL,NULL,'soltero','activo','2024-07-18 15:04:05',NULL),
(8,'Luis','Quispe',1,'98758931','M','30',NULL,NULL,'soltero','activo','2024-07-18 15:05:26',NULL),
(9,'Luis','Quispe',1,'98758932','M','30',NULL,NULL,'soltero','activo','2024-07-18 15:05:56',NULL),
(11,'Luis','Quispe',1,'98758933','M','30',NULL,NULL,'soltero','activo','2024-07-18 15:07:02',NULL),
(16,'Luis','Quispe',1,'98758934','M','30',NULL,NULL,'soltero','activo','2024-07-18 15:12:35',NULL),
(18,'Luis','Quispe',1,'98758935','M','30',NULL,NULL,'soltero','activo','2024-07-18 15:15:13',NULL),
(20,'Luis','Quispe',1,'98758936','M','30',NULL,NULL,'soltero','activo','2024-07-18 15:23:31',NULL),
(21,'david','',NULL,NULL,NULL,NULL,NULL,NULL,'soltero','activo','2024-07-18 20:32:47',NULL),
(22,'david','',NULL,NULL,NULL,NULL,NULL,NULL,'soltero','activo','2024-07-18 20:33:56',NULL),
(23,'david','',NULL,NULL,NULL,NULL,NULL,NULL,'soltero','activo','2024-07-18 20:37:13',NULL),
(24,'david','',NULL,NULL,NULL,NULL,NULL,NULL,'soltero','activo','2024-07-18 20:37:30',NULL),
(25,'david','',NULL,NULL,NULL,NULL,NULL,NULL,'soltero','activo','2024-07-18 20:39:33',NULL),
(26,'Juan Perez','',NULL,NULL,NULL,NULL,NULL,NULL,'soltero','activo','2024-07-18 21:20:40',NULL);

/*Table structure for table `productos` */

DROP TABLE IF EXISTS `productos`;

CREATE TABLE `productos` (
  `id` int NOT NULL AUTO_INCREMENT,
  `descripcion` varchar(250) NOT NULL,
  `precio` decimal(10,0) NOT NULL,
  `cantidad_stock` int NOT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `fecha_creado` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `fecha_actualizado` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

/*Data for the table `productos` */

insert  into `productos`(`id`,`descripcion`,`precio`,`cantidad_stock`,`estado`,`fecha_creado`,`fecha_actualizado`) values 
(1,'botella de agua cielo',5,100,'activo','2024-06-28 13:24:03',NULL);

/*Table structure for table `reservas` */

DROP TABLE IF EXISTS `reservas`;

CREATE TABLE `reservas` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_cliente` int NOT NULL,
  `id_habitacion` int NOT NULL,
  `id_empleado` int NOT NULL,
  `monto_total` decimal(10,2) NOT NULL,
  `fecha_reserva` datetime DEFAULT NULL,
  `fecha_entrada` datetime DEFAULT NULL,
  `fecha_salida` datetime DEFAULT NULL,
  `estado` enum('activo','pendiente_pago','pagado','cancelado') DEFAULT 'activo',
  `fecha_creado` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `fecha_actualizado` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `id_cliente` (`id_cliente`),
  KEY `id_habitacion` (`id_habitacion`),
  KEY `id_empleado` (`id_empleado`),
  CONSTRAINT `reservas_ibfk_1` FOREIGN KEY (`id_cliente`) REFERENCES `clientes` (`id`),
  CONSTRAINT `reservas_ibfk_2` FOREIGN KEY (`id_habitacion`) REFERENCES `habitaciones` (`id`),
  CONSTRAINT `reservas_ibfk_3` FOREIGN KEY (`id_empleado`) REFERENCES `empleados` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

/*Data for the table `reservas` */

insert  into `reservas`(`id`,`id_cliente`,`id_habitacion`,`id_empleado`,`monto_total`,`fecha_reserva`,`fecha_entrada`,`fecha_salida`,`estado`,`fecha_creado`,`fecha_actualizado`) values 
(1,1,1,1,89.90,'2023-11-10 18:45:29','2023-11-10 18:45:29','2023-11-10 18:45:29','activo','2024-06-28 13:24:03',NULL);

/*Table structure for table `reservas_consumo` */

DROP TABLE IF EXISTS `reservas_consumo`;

CREATE TABLE `reservas_consumo` (
  `id` int NOT NULL AUTO_INCREMENT,
  `id_reserva` int NOT NULL,
  `id_producto` int NOT NULL,
  `cantidad` int NOT NULL,
  `precio` decimal(10,2) NOT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `fecha_creado` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `fecha_actualizado` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

/*Data for the table `reservas_consumo` */

insert  into `reservas_consumo`(`id`,`id_reserva`,`id_producto`,`cantidad`,`precio`,`estado`,`fecha_creado`,`fecha_actualizado`) values 
(1,1,1,3,5.50,'activo','2024-06-28 13:24:03',NULL);

/*Table structure for table `tipo_habitacion` */

DROP TABLE IF EXISTS `tipo_habitacion`;

CREATE TABLE `tipo_habitacion` (
  `id` int NOT NULL AUTO_INCREMENT,
  `descripcion` varchar(250) NOT NULL,
  `fecha_creado` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `fecha_actualizado` datetime DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

/*Data for the table `tipo_habitacion` */

insert  into `tipo_habitacion`(`id`,`descripcion`,`fecha_creado`,`fecha_actualizado`) values 
(1,'clasico','2024-06-28 13:24:03',NULL);

/*Table structure for table `usuarios` */

DROP TABLE IF EXISTS `usuarios`;

CREATE TABLE `usuarios` (
  `id` int NOT NULL AUTO_INCREMENT,
  `nombres` varchar(100) NOT NULL,
  `apellidos` varchar(100) NOT NULL,
  `rol` enum('cliente','empleado','admin') NOT NULL,
  `username` varchar(100) NOT NULL,
  `pwd` varchar(250) NOT NULL,
  `estado` enum('activo','inactivo') DEFAULT 'activo',
  `fecha_creado` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `fecha_actualizado` datetime DEFAULT NULL,
  `fecha_eliminado` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`,`estado`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

/*Data for the table `usuarios` */

insert  into `usuarios`(`id`,`nombres`,`apellidos`,`rol`,`username`,`pwd`,`estado`,`fecha_creado`,`fecha_actualizado`,`fecha_eliminado`) values 
(1,'Alex','Quispe','empleado','alex.quispe@gmail.com','12345678','activo','2024-06-28 13:24:02',NULL,NULL),
(2,'Maria','Gonzales','cliente','maria.gonzales@utp.edu.pe','12345678','activo','2024-06-28 13:24:02',NULL,NULL),
(3,'Susan','Torres','cliente','susan.torres@utp.edu.pe','12345678','activo','2024-06-28 13:24:02',NULL,NULL),
(4,'david','','cliente','david@gmail.com','12345678','activo','2024-07-18 20:39:33',NULL,NULL),
(5,'Juan Perez','','cliente','jperez@gmail.com','12345678','activo','2024-07-18 21:20:40',NULL,NULL);

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
