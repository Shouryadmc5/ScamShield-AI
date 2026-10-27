import { useEffect, useMemo, useRef } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import {
  DoubleSide,
  ExtrudeGeometry,
  MathUtils,
  MeshBasicMaterial,
  Shape,
} from 'three';
import type { Group, Mesh } from 'three';

const SIGNALS = [
  { position: [0, 1.78, 0.06] as [number, number, number], color: '#B7FF4A', scale: 0.06 },
  { position: [-1.65, -0.52, 0.1] as [number, number, number], color: '#929A8E', scale: 0.04 },
  { position: [1.48, 0.92, -0.08] as [number, number, number], color: '#FF5B64', scale: 0.035 },
];

function Shield() {
  const shieldRef = useRef<Group>(null);
  const beamRef = useRef<Mesh>(null);
  const timeRef = useRef(0);

  const geometry = useMemo(() => {
    const shape = new Shape();
    shape.moveTo(0, 1.35);
    shape.quadraticCurveTo(-0.5, 1.12, -1.05, 0.92);
    shape.lineTo(-0.98, -0.12);
    shape.quadraticCurveTo(-0.84, -0.88, 0, -1.38);
    shape.quadraticCurveTo(0.84, -0.88, 0.98, -0.12);
    shape.lineTo(1.05, 0.92);
    shape.quadraticCurveTo(0.5, 1.12, 0, 1.35);
    return new ExtrudeGeometry(shape, {
      depth: 0.18,
      bevelEnabled: true,
      bevelSegments: 4,
      steps: 1,
      bevelSize: 0.055,
      bevelThickness: 0.045,
      curveSegments: 10,
    });
  }, []);
  const innerShape = useMemo(() => {
    const shape = new Shape();
    shape.moveTo(0.55, 0.62);
    shape.lineTo(-0.43, 0.62);
    shape.lineTo(-0.58, 0.47);
    shape.lineTo(-0.58, 0.17);
    shape.lineTo(-0.43, 0.02);
    shape.lineTo(0.38, 0.02);
    shape.lineTo(0.48, -0.08);
    shape.lineTo(0.48, -0.18);
    shape.lineTo(0.38, -0.28);
    shape.lineTo(-0.58, -0.28);
    shape.lineTo(-0.58, -0.48);
    shape.lineTo(-0.43, -0.62);
    shape.lineTo(0.43, -0.62);
    shape.lineTo(0.58, -0.48);
    shape.lineTo(0.58, -0.02);
    shape.lineTo(0.43, 0.13);
    shape.lineTo(-0.38, 0.13);
    shape.lineTo(-0.48, 0.23);
    shape.lineTo(-0.48, 0.32);
    shape.lineTo(-0.38, 0.42);
    shape.lineTo(0.55, 0.42);
    shape.closePath();
    return shape;
  }, []);

  useFrame(({ pointer }, delta) => {
    timeRef.current += delta;
    const time = timeRef.current;
    if (shieldRef.current) {
      shieldRef.current.rotation.y = MathUtils.damp(
        shieldRef.current.rotation.y,
        pointer.x * 0.18 + Math.sin(time * 0.35) * 0.07,
        3,
        delta,
      );
      shieldRef.current.rotation.x = MathUtils.damp(
        shieldRef.current.rotation.x,
        -pointer.y * 0.1,
        3,
        delta,
      );
      shieldRef.current.position.y = Math.sin(time * 0.7) * 0.045;
    }
    if (beamRef.current) {
      beamRef.current.position.y = Math.sin(time * 0.65) * 0.92;
      if (beamRef.current.material instanceof MeshBasicMaterial) {
        beamRef.current.material.opacity = 0.46 + Math.sin(time * 0.65) * 0.12;
      }
    }
  });

  return (
    <group scale={0.72}>
      <mesh rotation={[0.08, 0, 0]} scale={1.62}>
        <torusGeometry args={[1.08, 0.003, 6, 88]} />
        <meshBasicMaterial color="#929A8E" transparent opacity={0.24} />
      </mesh>
      <mesh rotation={[0.72, 0.35, 0.2]} scale={1.94}>
        <torusGeometry args={[1.08, 0.0025, 6, 88]} />
        <meshBasicMaterial color="#B7FF4A" transparent opacity={0.35} />
      </mesh>
      <group ref={shieldRef} rotation={[0, -0.24, -0.06]}>
        <mesh geometry={geometry} position={[0, 0, -0.09]}>
          <meshPhysicalMaterial
            color="#A3C878"
            emissive="#354b19"
            emissiveIntensity={0.08}
            metalness={0.18}
            roughness={0.3}
            transmission={0.72}
            thickness={0.4}
            transparent
            opacity={0.42}
            side={DoubleSide}
          />
        </mesh>
        <mesh position={[0, 0, 0.15]}>
          <shapeGeometry args={[innerShape]} />
          <meshBasicMaterial color="#080A08" side={DoubleSide} />
        </mesh>
        <mesh ref={beamRef} position={[0, 0, 0.18]}>
          <boxGeometry args={[1.64, 0.012, 0.018]} />
          <meshBasicMaterial color="#F2F5EE" transparent opacity={0.38} />
        </mesh>
        <mesh position={[0, -0.02, 0.19]}>
          <torusGeometry args={[0.19, 0.014, 8, 32, Math.PI]} />
          <meshBasicMaterial color="#080A08" transparent opacity={0.9} />
        </mesh>
      </group>
      <OrbitSignals />
    </group>
  );
}

function OrbitSignals() {
  const orbitRef = useRef<Group>(null);
  const timeRef = useRef(0);
  useFrame((_, delta) => {
    timeRef.current += delta;
    if (orbitRef.current) orbitRef.current.rotation.z = timeRef.current * 0.075;
  });
  return (
    <group ref={orbitRef}>
      {SIGNALS.map((signal) => (
        <mesh key={signal.position.join(',')} position={signal.position} scale={signal.scale}>
          <icosahedronGeometry args={[1, 1]} />
          <meshBasicMaterial color={signal.color} />
        </mesh>
      ))}
    </group>
  );
}

function FrameDriver() {
  const canvas = useThree((state) => state.gl.domElement);
  const invalidate = useThree((state) => state.invalidate);

  useEffect(() => {
    let isIntersecting = false;
    let interval: number | undefined;
    const refresh = () => {
      if (interval !== undefined) window.clearInterval(interval);
      if (isIntersecting && !document.hidden) {
        invalidate();
        interval = window.setInterval(invalidate, 1000 / 30);
      }
    };
    const observer = new IntersectionObserver(([entry]) => {
      isIntersecting = entry.isIntersecting;
      refresh();
    });
    observer.observe(canvas);
    document.addEventListener('visibilitychange', refresh);

    return () => {
      observer.disconnect();
      document.removeEventListener('visibilitychange', refresh);
      if (interval !== undefined) window.clearInterval(interval);
    };
  }, [canvas, invalidate]);

  return null;
}

export default function HeroScene() {
  return (
    <Canvas
      className="hero-canvas"
      dpr={window.matchMedia('(max-width: 640px)').matches ? 1 : [1, 1.35]}
      camera={{ position: [0, 0, 5.4], fov: 38 }}
      gl={{ alpha: true, antialias: true, powerPreference: 'low-power' }}
      frameloop="demand"
      fallback={<div className="static-shield" aria-hidden="true"><svg viewBox="0 0 32 36"><path d="M16 2 29 6v10c0 8-5.3 14.3-13 18C8.3 30.3 3 24 3 16V6L16 2Z" /><path d="M22 10h-9l-2 2v3l2 2h7l2 2v3l-2 2H10" /></svg></div>}
      aria-hidden="true"
    >
      <ambientLight intensity={0.8} />
      <pointLight position={[3, 2, 4]} color="#B7FF4A" intensity={24} />
      <pointLight position={[-3, -2, 2]} color="#929A8E" intensity={12} />
      <FrameDriver />
      <Shield />
    </Canvas>
  );
}
